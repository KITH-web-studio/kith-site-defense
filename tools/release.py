"""Build a candidate, verify it on two disposable WordPress sites, then publish the tested ZIP."""

import argparse
import gzip
import hashlib
import hmac
import ipaddress
import json
import math
import os
from pathlib import Path
from queue import Queue
import re
import shutil
from statistics import median
import subprocess
from tempfile import TemporaryDirectory, TemporaryFile
from threading import Thread
from time import perf_counter, sleep, time
from urllib.parse import urlsplit
from zipfile import ZipFile

import polib
import requests


ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / 'site-defense'
TESTS = ROOT / 'tests'
SOURCE_SUFFIXES = {'.php', '.css', '.json', '.po', '.md', '.py', '.ps1'}
SEED = ROOT / 'site-defense-wordfence-database.pack'


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def run(args, code=0, answer=None, timeout=120):
    result = subprocess.run(args, cwd=ROOT, input=answer, encoding='utf-8', errors='replace',
                            capture_output=True, timeout=timeout)
    codes = (code,) if isinstance(code, int) else code
    if result.returncode not in codes:
        raise RuntimeError(f'{Path(args[0]).name} exited {result.returncode}: {result.stderr[:1700]} {result.stdout[:600]}')
    require(not re.search(r'(?:PHP Fatal error|WordPress database error)', result.stderr), 'PHP or database error in test.')
    return result.stdout.strip()


def header(name):
    source = (PLUGIN / 'site-defense.php').read_text(encoding='utf-8')
    return re.search(rf'^ \* {re.escape(name)}: (.+)$', source, re.MULTILINE)[1]


def artifacts(archive, php, database, rules, version):
    for folder in (PLUGIN, TESTS, ROOT / 'tools'):
        for file in folder.rglob('*'):
            if file.is_file() and file.suffix in SOURCE_SUFFIXES:
                data = file.read_bytes()
                require(not data.startswith(b'\xef\xbb\xbf'), f'BOM in {file.name}')
                data.decode('utf-8')
                if file.suffix == '.php':
                    run([php, '-l', str(file)])
    for test in ('db-audit-signals.php', 'request-correlation.php'):
        run([php, str(TESTS / test)])
    with ZipFile(archive) as package:
        sources = {file.relative_to(ROOT).as_posix(): file for file in PLUGIN.rglob('*') if file.is_file()}
        actual = [item.filename for item in package.infolist() if not item.is_dir()]
        require(sorted(actual) == sorted(sources) and package.testzip() is None, 'ZIP structure or CRC mismatch.')
        for entry, source in sources.items():
            require(package.read(entry) == source.read_bytes(), f'ZIP bytes differ for {entry}.')
    run([php, str(TESTS / 'release-signatures.php'), str(PLUGIN / 'data/update.json'), str(SEED), str(database), str(rules)])
    packed = (PLUGIN / 'data/vulnerabilities.json.gz').read_bytes()
    require(SEED.read_bytes()[64:] == packed, 'The signed Wordfence package differs from the bundled data.')
    config = json.loads((PLUGIN / 'data/update.json').read_text(encoding='utf-8'))
    with gzip.open(PLUGIN / 'data/vulnerabilities.json.gz', 'rt', encoding='utf-8') as data:
        metadata = json.loads(next(data))
        records = sum(1 for line in data if json.loads(line))
    require(metadata['version'] == config['seed_version'] and records > 10000, 'Expected the full Wordfence seed.')
    messages = set()
    for file in PLUGIN.rglob('*.php'):
        messages.update(re.findall(r"(?:__|esc_html__|esc_attr__)\(\s*'((?:\\.|[^'\\])*)'\s*,\s*'site-defense'",
                                   file.read_text(encoding='utf-8')))
    messages = {message.replace("\\'", "'") for message in messages}
    counts = {}
    placeholders = re.compile(r'%(?:[0-9]+\$)?[ds]')
    for locale in ('ru_RU', 'uk'):
        file = PLUGIN / 'languages' / f'site-defense-{locale}.po'
        po = polib.pofile(file, encoding='utf-8')
        mo = polib.mofile(file.with_suffix('.mo'))
        localized = {entry.msgid: entry.msgstr for entry in po.translated_entries()}
        require(po.metadata.get('Project-Id-Version') == 'Site Defense ' + version, f'{locale} catalog version mismatch.')
        require(messages <= localized.keys() and localized == {entry.msgid: entry.msgstr for entry in mo}, f'{locale} translation mismatch.')
        for msgid, translation in localized.items():
            require(sorted(placeholders.findall(msgid)) == sorted(placeholders.findall(translation)), f'{locale} placeholder mismatch.')
        counts[locale] = len(localized)
    return {'signed_wordfence_component_rows': records, 'feed_version': metadata['version'], 'translations': counts,
            'zip_structure_and_bytes': 'passed', 'php_lint_and_standalone_tests': 'passed'}


class Site:
    def __init__(self, arguments, wp_cli, commerce):
        path, url, php, log, password = arguments
        self.home = url.rstrip('/')
        self.origin = urlsplit(self.home)
        require(self.origin.scheme in ('http', 'https') and self.origin.username is None and
                self.origin.hostname is not None and ipaddress.ip_address(self.origin.hostname).is_loopback and
                not (self.origin.path or self.origin.query or self.origin.fragment), 'Use a loopback lab URL.')
        self.path = Path(path).resolve(strict=True)
        self.cmd = [str(Path(shutil.which(php) or php).resolve(strict=True)), str(wp_cli), '--path=' + str(self.path)]
        self.log = Path(log).resolve(strict=True)
        self.password = Path(password).read_text(encoding='utf-8').strip()
        self.commerce = commerce
        self.name = 'WooCommerce' if commerce else 'WordPress'
        self.environment = json.loads(self.fixture('environment'))
        require(self.environment['home'].rstrip('/') == self.home and self.environment['sodium'] and
                bool(self.environment['woocommerce']) == commerce and (not commerce or self.environment['hpos']),
                f'Unexpected WordPress fixture for {self.name}. Enable HPOS on the shop fixture.')

    def wp(self, *args, user=1, **options):
        return run([*self.cmd, f'--user={user}', *map(str, args)], **options)

    def fixture(self, *args):
        return self.wp('eval-file', TESTS / 'release-site.php', *args)

    def defense(self, *args, **options):
        return self.wp('site-defense', *args, **options)

    def install(self, archive):
        self.wp('plugin', 'install', archive, '--force', '--activate')

    @staticmethod
    def session():
        session = requests.Session()
        session.trust_env = False
        return session

    def http(self, session, method, url, status=200, **options):
        address = self.home + url if url.startswith('/') else url
        for _ in range(6):
            parsed = urlsplit(address)
            require(parsed.netloc == self.origin.netloc and parsed.scheme == self.origin.scheme, 'Unexpected redirect outside the test site.')
            response = session.request(method, address, allow_redirects=False, timeout=20, **options)
            if response.status_code in (301, 302, 303, 307, 308) and status == 200 and method == 'GET':
                address = requests.compat.urljoin(address, response.headers['Location'])
                continue
            codes = (status,) if isinstance(status, int) else status
            require(response.status_code in codes and 'There has been a critical error' not in response.text,
                    f'{self.name} {method} {parsed.path} returned {response.status_code}, expected {status}: {response.text[:450]}')
            return response
        raise RuntimeError('Too many WordPress redirects.')

    def login(self, username, password, page='/wp-login.php'):
        session = self.session()
        self.http(session, 'GET', page)
        self.http(session, 'POST', page, status=302, data={'log': username, 'pwd': password, 'testcookie': 1})
        return session

    def mcp(self, user, calls, between=None):
        command = [*self.cmd, '--quiet', f'--user={user}', 'site-defense', 'mcp', '--access-log=' + str(self.log)]
        with TemporaryFile() as errors, subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                                        stderr=errors, encoding='utf-8', bufsize=1) as proc:
            responses = Queue()
            def read_lines():
                for line in proc.stdout:
                    responses.put(line)
                responses.put(None)
            reader = Thread(target=read_lines, daemon=True)
            reader.start()
            def send(method, params=None, id=None):
                body = {'jsonrpc': '2.0', 'method': method}
                if params is not None:
                    body['params'] = params
                if id is not None:
                    body['id'] = id
                proc.stdin.write(json.dumps(body) + '\n')
                proc.stdin.flush()
                if id is not None:
                    line = responses.get(timeout=45)
                    require(line is not None, 'MCP exited unexpectedly.')
                    response = json.loads(line)
                    require(response.get('id') == id, 'MCP response ID mismatch.')
                    return response
            try:
                init = send('initialize', {'protocolVersion': '2025-11-25'}, 1)
                send('notifications/initialized')
                result = []
                for index, (name, args) in enumerate(calls, 2):
                    if index > 2 and between:
                        between()
                    result.append(send('tools/call', {'name': name, 'arguments': args}, index))
                return init['result']['serverInfo']['version'], result
            finally:
                proc.stdin.close()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()


def mcp_report(site, tool, args, user, version):
    advertised, (response,) = site.mcp(user, [(tool, args)])
    require(advertised == version and response.get('result', {}).get('isError') is False, f'MCP {tool} failed: {response}')
    return response['result']['structuredContent']


def platform(site, candidate, previous, version):
    if 'site-defense/site-defense.php' in site.environment['plugins']:
        site.wp('plugin', 'deactivate', 'site-defense')
    site.install(candidate)
    require(site.wp('plugin', 'get', 'site-defense', '--field=version') == version, 'Clean installation version mismatch.')
    site.defense('status')
    site.http(site.session(), 'GET', '/')
    site.wp('plugin', 'deactivate', 'site-defense')
    site.install(previous)
    old = site.wp('plugin', 'get', 'site-defense', '--field=version')
    require(old != version, 'The upgrade and rollback ZIP must be a previous release.')
    return old


def signed_updates(site, database, rules, temporary):
    def broken(path):
        data = path.read_bytes()
        target = temporary / ('invalid-' + path.name)
        target.write_bytes(bytes([data[0] ^ 1]) + data[1:])
        return target
    initial = json.loads(site.defense('database', 'status'))
    site.defense('database', 'import', broken(database), code=1)
    site.defense('database', 'import', database)
    current = json.loads(site.defense('database', 'status'))
    require(current['version'] > initial['version'] and current['status']['success'] > 0, 'Signed import or update timestamp failed.')
    site.defense('database', 'import', database, code=1)
    require(json.loads(site.defense('database', 'status'))['status']['success'] == current['status']['success'], 'Replayed import changed the success timestamp.')
    initial = json.loads(site.defense('rules', 'status'))['version']
    site.defense('rules', 'import', broken(rules), code=1)
    site.defense('rules', 'import', rules)
    site.defense('rules', 'rollback', '--yes')
    require(json.loads(site.defense('rules', 'status'))['version'] == initial, 'Signed WAF rollback failed.')
    site.defense('rules', 'import', rules, code=1)


def checkout(site, data):
    guest = site.session()
    checkout_page = '/?page_id=' + str(data['checkout'])
    site.http(guest, 'GET', '/?add-to-cart=' + str(data['product']))
    require('wp-block-woocommerce-checkout' in site.http(guest, 'GET', checkout_page).text, 'Checkout Block is absent.')
    api = '/?rest_route=/wc/store/v1/'
    headers = {'Cart-Token': site.http(guest, 'GET', api + 'cart').headers['Cart-Token']}
    site.http(guest, 'POST', api + 'cart/add-item', status=201, headers=headers, json={'id': data['product'], 'quantity': 1})
    address = {'first_name': 'Local', 'last_name': 'Release', 'address_1': '1 Test Street', 'city': 'New York',
               'state': 'NY', 'postcode': '10001', 'country': 'US', 'email': 'sd-release@example.test', 'phone': '2125550100'}
    response = site.http(guest, 'POST', api + 'checkout', headers=headers, json={'billing_address': address,
        'shipping_address': {key: value for key, value in address.items() if key not in ('email', 'phone')},
        'payment_method': 'cod', 'payment_data': []}).json()
    require(response['payment_result']['payment_status'] == 'success', 'Checkout did not complete.')
    return response['order_id']


def payment(site, order):
    site.fixture('order', order, 'pending')
    body = json.dumps({'order_id': order})
    signature = hmac.new(b'site-defense-local-release-fixture', body.encode(), hashlib.sha256).hexdigest()
    path = '/?wc-api=sd_release_payment'
    guest = site.session()
    site.http(guest, 'POST', path, status=401, data=body, headers={'X-SD-Release-Signature': 'invalid'})
    for _ in range(2):
        response = site.http(guest, 'POST', path, data=body, headers={'X-SD-Release-Signature': signature})
        require(response.json() == {'paid': True, 'transaction': 'release-local-transaction'}, 'Payment callback or replay failed.')
    snapshot = json.loads(site.fixture('order', order))
    require(snapshot['rows']['wc_orders'] and snapshot['rows']['woocommerce_order_items'], 'HPOS order or line item missing.')
    return snapshot


def mutations(site, data, candidate, previous, plans, version, old, orders):
    site.defense('db-audit', 'run', '--timeout=0')
    catalog = json.loads(site.defense('investigate', '--limit=200'))['cleanup_targets']
    content_id = next(key for key, row in catalog.items() if row['target'] == f"posts/{data['post']}/post_content")
    file_id = next(key for key, row in catalog.items() if row['target'] == data['relative'])
    legacy = json.loads(site.defense('cleanup', 'prepare', ','.join([content_id, file_id])))
    plans.append(legacy['id'])
    site.install(candidate)
    require(json.loads(site.defense('cleanup', 'show', legacy['id'])) == legacy, 'Upgrade lost the previous version plan.')
    user = data['user']
    report = mcp_report(site, 'site_defense_investigate', {'limit': 200}, user, version)
    require(content_id in report['cleanup_targets'] and 'sd-release-private' not in json.dumps(report), 'Unexpected MCP findings or private data.')
    plan = mcp_report(site, 'site_defense_prepare_cleanup', {'targets': [content_id, file_id]}, user, version)
    plan_id = plan['id']
    plans.append(plan_id)
    require(all('backup' not in item for item in plan['steps'].values()), 'MCP exposed a private backup.')
    preview = json.loads(site.defense('cleanup', 'preview', plan_id, content_id))
    require(preview['status'] == 'pending' and '&lt;script' in preview['fragments'][0]['snippet'], 'Unsafe or missing cleanup preview.')
    site.defense('cleanup', 'preview', plan_id, content_id, user=user, code=1)
    site.defense('cleanup', 'apply', plan_id, content_id, '--yes', user=user, code=1)
    site.defense('cleanup', 'apply', plan_id, content_id, answer='n\n', code=(0, 1))
    require(site.fixture('content') == data['original_hash'], 'Cancelled cleanup changed the content.')
    site.fixture('drift')
    site.defense('cleanup', 'apply', plan_id, content_id, '--yes', code=1)
    site.fixture('drift', 'restore')
    order = checkout(site, data) if site.commerce else None
    if order:
        orders.append(order)
        snapshot = payment(site, order)
    for step in (content_id, file_id):
        site.defense('cleanup', 'apply', plan_id, step, answer='y\n')
    site.fixture('stage', plan_id, content_id, 'applying')
    site.defense('cleanup', 'apply', plan_id, content_id, '--yes')
    verified = mcp_report(site, 'site_defense_verify_cleanup', {'plan_id': plan_id}, user, version)
    require(verified['summary'] == {'verified': 2}, 'File or database mutation did not verify.')
    if order:
        require(json.loads(site.fixture('order', order)) == snapshot, 'Apply changed the HPOS order snapshot.')
    for step in (content_id, file_id):
        site.defense('cleanup', 'undo', plan_id, step, answer='y\n')
    site.fixture('stage', plan_id, content_id, 'undoing')
    site.defense('cleanup', 'undo', plan_id, content_id, '--yes')
    restored = json.loads(site.defense('cleanup', 'verify', plan_id))
    require(restored['summary'] == {'undone': 2} and site.fixture('content') == data['original_hash'], 'Cleanup undo changed original content.')
    if order:
        require(json.loads(site.fixture('order', order)) == snapshot, 'Undo changed the HPOS order snapshot.')
    site.install(previous)
    require(site.wp('plugin', 'get', 'site-defense', '--field=version') == old and
            json.loads(site.defense('cleanup', 'verify', plan_id))['summary'] == {'undone': 2}, 'ZIP downgrade lost the history.')
    site.install(candidate)


def access_checks(site, data, user, version):
    admin = site.login('sdrelease-admin', site.password)
    site.http(admin, 'GET', '/wp-admin/admin.php?page=site-defense')
    target = '/wp-admin/admin-post.php'
    form = {'action': 'sd_action', 'task': 'early_install', 'confirm': 'yes'}
    site.http(admin, 'POST', target, status=403, data=form | {'_wpnonce': 'invalid'})
    subscriber = site.login(data['login_name'], data['password'])
    site.http(subscriber, 'POST', target, status=403, data=form)
    require(not (site.path / '.sd-early.json').exists(), 'Unauthorized early configuration change.')
    tool = ('site_defense_investigate', {'limit': 80})
    def revoke():
        site.wp('user', 'remove-cap', user, 'site_defense_investigate')
    advertised, (before, after) = site.mcp(user, [tool, tool], between=revoke)
    require(advertised == version and 'result' in before and after.get('error', {}).get('code') == -32001, 'MCP did not observe revoked access.')
    site.defense('mcp', user=user, code=1, answer='')
    site.wp('user', 'add-cap', user, 'site_defense_investigate')


def early_and_login(site, data, version):
    guest = site.session()
    site.http(guest, 'GET', data['url'])
    notice = site.wp('eval', r'echo \SiteDefense\EarlyProtection::install();')
    require((site.path / '.sd-early.json').exists(), 'Early WAF installation failed: ' + notice)
    forged = 'forged-client-trace-1234'
    for _ in range(20):
        response = site.http(guest, 'GET', data['url'], status=(200, 403),
                             headers={'X-Request-ID': forged, 'Site-Defense-Request-ID': forged})
        if response.status_code == 403:
            break
        sleep(0.25)
    require(response.status_code == 403, 'FastCGI did not load the early firewall.')
    site.wp('eval', r'\SiteDefense\EarlyProtection::drain();')
    report = mcp_report(site, 'site_defense_investigate', {'limit': 80}, data['user'], version)
    require(forged not in json.dumps(report) and any(group['status'] == 'confirmed' and any(
        event['rule'] == 'UPLOADS-PHP' and event['layer'] == 'early' and event['path'] == urlsplit(data['url']).path
        for event in group['sources']['waf'])
        for group in report['request_correlation']['requests']), 'Early WAF/FastCGI request correlation failed.')
    site.wp('eval', r'echo \SiteDefense\LoginRoute::propose("sd-release-enter", get_current_user_id());')
    site.login('sdrelease-admin', site.password, '/sd-release-enter/')
    site.http(guest, 'GET', '/wp-login.php', status=404)
    site.wp('plugin', 'deactivate', 'site-defense')
    require(not (site.path / '.sd-early.json').exists(), 'Deactivation left early protection enabled.')
    site.http(guest, 'GET', data['url'])
    site.login('sdrelease-admin', site.password)
    site.wp('plugin', 'activate', 'site-defense')
    site.wp('option', 'delete', 'sd_login_route')


def timings(values):
    ordered = sorted(values)
    return {'requests': len(ordered), 'median_ms': round(median(ordered), 2),
            'p95_ms': round(ordered[math.ceil(len(ordered) * 0.95) - 1], 2)}


def performance(site, data, samples):
    client = site.session()
    routes = {'home': '/'}
    if site.commerce:
        site.http(client, 'GET', '/?add-to-cart=' + str(data['product']))
        routes['product'] = '/?p=' + str(data['product'])
        routes['cart'] = '/?page_id=' + site.wp('option', 'get', 'woocommerce_cart_page_id')
        routes['checkout'] = '/?page_id=' + str(data['checkout'])
    def sample(route):
        start = perf_counter()
        site.http(client, 'GET', route)
        return (perf_counter() - start) * 1000
    def series():
        return {key: timings([sample(route) for _ in range(samples + 3)][3:]) for key, route in routes.items()}
    site.wp('plugin', 'deactivate', 'site-defense')
    baseline = series()
    site.wp('plugin', 'activate', 'site-defense')
    idle = series()
    active = {key: [] for key in routes}
    runs = []
    while any(len(values) < samples for values in active.values()):
        require(len(runs) < 6, 'Too few requests completed during six scan runs.')
        with TemporaryFile() as stdout, TemporaryFile() as stderr, subprocess.Popen(
            [*site.cmd, '--user=1', 'site-defense', 'scan', 'run', '--timeout=0'], stdout=stdout, stderr=stderr,
        ) as scan:
            start = perf_counter()
            try:
                while scan.poll() is None and any(len(values) < samples for values in active.values()):
                    for key, route in routes.items():
                        if scan.poll() is None and len(active[key]) < samples:
                            duration = sample(route)
                            if scan.poll() is None:
                                active[key].append(duration)
                    require(perf_counter() - start < 180, 'Scanner did not finish within 180 seconds.')
                require(scan.wait(timeout=180) == 0, 'CLI scan failed during the release benchmark.')
            finally:
                if scan.poll() is None:
                    scan.kill()
            stdout.seek(0)
            result = json.load(stdout)
            require(result['status'] == 'complete' and not result.get('report_error'), 'Incomplete background scan.')
            stats = {key: result[key] for key in ('files', 'bytes_read', 'peak_memory_bytes', 'duration_seconds', 'skipped_count')}
            runs.append(stats | {'wall_seconds': round(perf_counter() - start, 3)})
    return {'baseline': baseline, 'idle': idle, 'scan': {key: timings(values) for key, values in active.items()},
            'scan_runs': runs, 'concurrent_clients': 1}


def acceptance(site, args, candidate, workspace, version):
    print(f'{site.name}: clean install, upgrade, security and rollback', flush=True)
    previous_version = platform(site, candidate, args.previous, version)
    plans, orders = [], []
    try:
        data = json.loads(site.fixture('setup', TESTS / 'release-payment.php'))
        mutations(site, data, candidate, args.previous, plans, version, previous_version, orders)
        access_checks(site, data, data['user'], version)
        early_and_login(site, data, version)
        signed_updates(site, args.database, args.rules, workspace)
        require(set(json.loads(site.fixture('alerts'))) == {'email', 'telegram'}, 'Mocked notification delivery failed.')
        site.wp('eval-file', TESTS / 'stored-html.php')
        site.wp('eval-file', TESTS / 'malware-analyzer.php')
        print(f'{site.name}: measuring warm HTTP responses and full CLI scan', flush=True)
        metrics = performance(site, data, args.samples)
        return {'environment': site.environment, 'upgrade_and_rollback_from': previous_version, 'acceptance': 'passed',
                'checkout_hpos_and_test_callback': 'passed' if site.commerce else None,
                'notifications': 'email and Telegram with mocked transports', 'performance': metrics}
    finally:
        # A failed phase may have left the prior ZIP or early protection active. Leave a usable lab.
        site.wp('plugin', 'activate', 'site-defense')
        site.wp('eval', r'\SiteDefense\EarlyProtection::disable();')
        site.fixture('restore', *plans, *[f'order:{id}' for id in orders])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ('plain', 'shop'):
        parser.add_argument('--' + flag, nargs=5, required=True, metavar=('WP_PATH', 'URL', 'PHP', 'PROXY_LOG', 'PASSWORD_FILE'))
    for flag in ('wp-cli', 'previous', 'database', 'rules', 'output', 'report'):
        parser.add_argument('--' + flag, type=lambda value: Path(value).resolve(), required=True)
    parser.add_argument('--samples', type=int, default=20)
    args = parser.parse_args()
    require(20 <= args.samples <= 100, 'Choose 20–100 measured requests per route.')
    require(args.output != args.report and args.output not in (args.database, args.rules, args.wp_cli), 'Choose a separate output ZIP.')
    version = header('Version')
    plain = Site(args.plain, args.wp_cli, False)
    shop = Site(args.shop, args.wp_cli, True)
    require(plain.path != shop.path and plain.home != shop.home, 'Use two separate WordPress installations.')
    require(plain.environment['wp'] == header('Requires at least') and
            plain.environment['php'].startswith(header('Requires PHP') + '.'), 'The standalone site must use the declared minimum versions.')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(prefix='.site-defense-release-', dir=args.output.parent) as directory:
        temporary = Path(directory)
        candidate = temporary / 'site-defense.zip'
        run(['pwsh', '-NoProfile', '-File', str(ROOT / 'tools/package.ps1'), '-Output', str(candidate)])
        report = {'version': version, 'measured_at': int(time()),
                  'artifact': artifacts(candidate, plain.cmd[0], args.database, args.rules, version), 'sites': {}}
        for key, site in [('wordpress', plain), ('woocommerce', shop)]:
            report['sites'][key] = acceptance(site, args, candidate, temporary, version)
        report['sha256'] = hashlib.sha256(candidate.read_bytes()).hexdigest()
        report['bytes'] = candidate.stat().st_size
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        os.replace(candidate, args.output)
        print(f'Release {version} verified. SHA-256 {report["sha256"]}', flush=True)


if __name__ == '__main__':
    main()
