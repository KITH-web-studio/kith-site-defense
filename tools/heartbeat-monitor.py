#!/usr/bin/env python3
"""Receive Site Defense signals on a separate host and report missed heartbeats."""

import argparse
from contextlib import contextmanager
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import sqlite3
import sys
import time
from urllib.request import Request, urlopen


@contextmanager
def state(path):
    db = sqlite3.connect(path, timeout=12)
    try:
        db.row_factory = sqlite3.Row
        db.execute("CREATE TABLE IF NOT EXISTS monitor (id INTEGER PRIMARY KEY, started INTEGER, "
                   "sent INTEGER DEFAULT 0, received INTEGER DEFAULT 0, issues TEXT DEFAULT '[]', "
                   "notified TEXT DEFAULT 'ok')")
        db.execute("INSERT OR IGNORE INTO monitor (id, started) VALUES (1, ?)", (int(time.time()),))
        db.commit()
        yield db
    finally:
        db.close()


def receiver(path, secret):
    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            self.request.settimeout(5)
            super().setup()

        def do_POST(self):
            if self.path != "/heartbeat":
                self.send_error(404)
                return
            raw_time = self.headers.get("X-Site-Defense-Time", "")
            signature = self.headers.get("X-Site-Defense-Signature", "")
            size = self.headers.get("Content-Length", "")
            now = int(time.time())
            if not re.fullmatch(r"[0-9]{10,12}", raw_time) or abs(now - int(raw_time)) > 300:
                self.send_error(401)
                return
            if not size.isascii() or not size.isdecimal() or len(size) > 4 or not 0 < int(size) <= 1024:
                self.send_error(400)
                return
            try:
                body = self.rfile.read(int(size))
            except TimeoutError:
                self.send_error(408)
                return
            expected = hmac.new(secret, raw_time.encode() + b"." + body, hashlib.sha256).hexdigest()
            if not re.fullmatch(r"[a-f0-9]{64}", signature) or not hmac.compare_digest(signature, expected):
                self.send_error(401)
                return
            try:
                payload = json.loads(body)
                healthy = payload["healthy"]
                issues = payload["issues"]
                if (payload["version"] != 1 or type(healthy) is not bool or not isinstance(issues, list)
                        or healthy != (not issues) or any(issue not in (
                            "alert_worker_stale", "file_watch_stale") for issue in issues)):
                    raise ValueError
            except (KeyError, TypeError, ValueError):
                self.send_error(400)
                return
            with state(path) as db:
                updated = db.execute("UPDATE monitor SET sent=?, received=?, issues=? WHERE id=1 AND sent<?",
                                     (int(raw_time), now, json.dumps(issues), int(raw_time))).rowcount
                db.commit()
            self.send_response(204 if updated else 409)
            self.end_headers()

    return Handler


def telegram(message):
    token = os.environ.get("SD_MONITOR_TELEGRAM_TOKEN", "")
    chat = os.environ.get("SD_MONITOR_TELEGRAM_CHAT", "")
    if not re.fullmatch(r"[0-9]{5,20}:[A-Za-z0-9_-]{20,100}", token) or not re.fullmatch(
            r"-?[0-9]{1,20}|@[A-Za-z0-9_]{5,32}", chat):
        raise ValueError("Set SD_MONITOR_TELEGRAM_TOKEN and SD_MONITOR_TELEGRAM_CHAT.")
    body = json.dumps({"chat_id": chat, "text": message, "disable_web_page_preview": True}).encode()
    request = Request(f"https://api.telegram.org/bot{token}/sendMessage", data=body,
                      headers={"Content-Type": "application/json"})
    try:
        with urlopen(request, timeout=8) as response:
            if json.loads(response.read(16384)).get("ok") is not True:
                raise OSError
    except (OSError, ValueError) as error:
        raise RuntimeError("External Telegram delivery failed.") from error


def check(path, timeout, report):
    with state(path) as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT * FROM monitor WHERE id=1").fetchone()
        issues = json.loads(row["issues"])
        elapsed = max(0, int(time.time()) - (row["received"] or row["started"]))
        if elapsed >= timeout:
            status = "missing"
        elif issues:
            status = "unhealthy"
        else:
            status = "ok" if row["received"] else "waiting"
        name = os.environ.get("SD_MONITOR_SITE_LABEL", "WordPress")
        if report and status != "waiting" and status != row["notified"]:
            messages = {
                "missing": f"No signed Site Defense heartbeat for {elapsed // 60} minutes.",
                "unhealthy": "The site is reachable. Stalled jobs: " + ", ".join(issues),
                "ok": "Site Defense heartbeat and jobs recovered.",
            }
            telegram(name + "\n" + messages[status])
            db.execute("UPDATE monitor SET notified=? WHERE id=1", (status,))
        db.commit()
    return {"status": status, "last_received": row["received"], "age_seconds": elapsed, "issues": issues}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True, help="Private SQLite state file")
    command = parser.add_subparsers(dest="command", required=True)
    serve = command.add_parser("serve")
    serve.add_argument("--bind", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8787)
    for action in ("check", "status"):
        task = command.add_parser(action)
        task.add_argument("--timeout", type=int, default=900, help="Seconds without a heartbeat")
    args = parser.parse_args()
    if args.command == "serve":
        secret = os.environ.get("SD_HEARTBEAT_SECRET", "")
        if not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", secret):
            parser.error("Set SD_HEARTBEAT_SECRET to 32–128 URL-safe characters.")
        with state(args.state):
            pass
        with ThreadingHTTPServer((args.bind, args.port), receiver(args.state, secret.encode())) as server:
            server.serve_forever()
        return
    if args.timeout < 300:
        parser.error("Set the timeout to at least 300 seconds.")
    print(json.dumps(check(args.state, args.timeout, args.command == "check"), ensure_ascii=False))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, sqlite3.Error) as error:
        sys.exit(str(error))
