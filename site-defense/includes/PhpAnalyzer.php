<?php
namespace SiteDefense;

defined('ABSPATH') || exit;

/** Bounded, intraprocedural taint tracking. Source code is tokenized, never executed. */
final class PhpAnalyzer
{
    private const REQUEST = 1;
    private const DECODED = 2;
    private const REMOTE = 4;
    private const PHP_CODE = 8;
    private const URL = 16;
    private const PHP_TARGET = 32;
    private const FIXED_BASE = 64;
    private array $tokens = [];
    private array $pairs = [];
    private array $hits = [];
    private array $variables = [];
    public bool $limited = false;
    private float $deadline = 0;

    public function __construct(private array $rules)
    {
    }

    public function analyze(string $source): array
    {
        $this->deadline = microtime(true) + 1.5;
        $line = 1;
        $offset = 0;
        $raw = token_get_all($source);
        $rawCount = count($raw);
        for ($index = 0; $index < $rawCount; $index++) {
            $token = $raw[$index];
            unset($raw[$index]);
            if (is_array($token)) {
                [$id, $text, $line] = $token;
            } else {
                $id = 0;
                $text = $token;
            }
            if (!in_array($id, [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT, T_INLINE_HTML, T_OPEN_TAG, T_CLOSE_TAG], true)) {
                if (is_array($token)) {
                    $token[3] = $offset;
                    $this->tokens[] = $token;
                } else {
                    $this->tokens[] = [$id, $text, $line, $offset];
                }
            }
            $line += substr_count($text, "\n");
            $offset += strlen($text);
        }
        $stack = [];
        foreach ($this->tokens as $index => $token) {
            if (($token[0] === 0 && in_array($token[1], ['(', '[', '{'], true)) ||
                in_array($token[0], [T_CURLY_OPEN, T_DOLLAR_OPEN_CURLY_BRACES, T_ATTRIBUTE], true)) {
                $stack[] = $index;
            } elseif ($token[0] === 0 && in_array($token[1], [')', ']', '}'], true) && $stack) {
                $open = array_pop($stack);
                $this->pairs[$open] = $index;
            }
        }
        $scopes = [];
        $depth = 0;
        $count = count($this->tokens);
        for ($i = 0; $i < $count; $i++) {
            if ($i % 128 === 0 && microtime(true) > $this->deadline) {
                $this->limited = true;
                break;
            }
            [$id, $text] = $this->tokens[$i];
            if ($id === T_FUNCTION || $id === T_FN) {
                $scopes[] = [$depth, $this->variables, $id === T_FN];
                $this->variables = [];
            }
            if ($id === 0 && $text === '{') {
                $depth++;
            } elseif ($id === 0 && $text === '}') {
                $depth--;
                if ($scopes && end($scopes)[0] === $depth) {
                    $this->variables = array_pop($scopes)[1];
                }
            } elseif ($text === ';' && $scopes && end($scopes)[2]) {
                $this->variables = array_pop($scopes)[1];
            }
            if ($id === T_VARIABLE) {
                $operator = $i + 1;
                while (($this->tokens[$operator][1] ?? '') === '[' && isset($this->pairs[$operator])) {
                    $operator = $this->pairs[$operator] + 1;
                }
                if (in_array($this->tokens[$operator][1] ?? '', ['=', '.='], true)) {
                    $start = $operator + 1;
                    $end = $this->statementEnd($start);
                    $flags = in_array($this->tokens[$start][0] ?? 0, [T_FUNCTION, T_FN], true)
                        ? 0 : $this->expression($start, $end);
                    $previous = $this->tokens[$operator][1] === '.=' ? ($this->variables[$text] ?? 0) : 0;
                    if (count($this->variables) < 4000 || isset($this->variables[$text])) {
                        $this->variables[$text] = $previous | $flags;
                    } else {
                        $this->limited = true;
                    }
                }
            }
            if ($this->callName($i) !== '') {
                $end = $this->pairs[$i + 1] ?? $this->statementEnd($i + 1);
                $this->expression($i, $end + 1);
            }
        }
        return array_values($this->hits);
    }

    private function statementEnd(int $start): int
    {
        $count = count($this->tokens);
        for ($i = $start; $i < $count; $i++) {
            if ($this->tokens[$i][0] === 0 && in_array($this->tokens[$i][1], [';', ',', '}', ')', ']'], true)) {
                return $i;
            }
            if (isset($this->pairs[$i])) {
                $i = $this->pairs[$i];
            }
        }
        return $count;
    }

    private function callName(int $index): string
    {
        [$id, $name] = $this->tokens[$index];
        if (in_array($this->tokens[$index - 1][0] ?? 0, [T_OBJECT_OPERATOR, T_NULLSAFE_OBJECT_OPERATOR, T_DOUBLE_COLON, T_FUNCTION, T_NEW], true)) {
            return '';
        }
        if (in_array($id, [T_INCLUDE, T_INCLUDE_ONCE, T_REQUIRE, T_REQUIRE_ONCE], true)) {
            return 'include';
        }
        if (($this->tokens[$index + 1][1] ?? '') !== '(' || !in_array($id, [T_STRING, T_NAME_FULLY_QUALIFIED, T_EVAL, T_VARIABLE], true)) {
            return '';
        }
        return $id === T_VARIABLE ? $name : strtolower(ltrim($name, '\\'));
    }

    private function expression(int $start, int $end, int $depth = 0): int
    {
        $end = min($end, count($this->tokens));
        if ($depth > 12 || microtime(true) > $this->deadline) {
            $this->limited = true;
            return 0;
        }
        $flags = 0;
        for ($i = $start; $i < $end; $i++) {
            [$id, $text, $line] = $this->tokens[$i];
            $name = $this->callName($i);
            if ($name !== '') {
                $open = $i + 1;
                $close = $this->pairs[$open] ?? min($this->statementEnd($open), $end);
                $arguments = [];
                $argumentStart = ($this->tokens[$open][1] ?? '') === '(' ? $open + 1 : $open;
                for ($j = $argumentStart; $j <= $close; $j++) {
                    if ($j === $close || $this->tokens[$j][1] === ',') {
                        $arguments[] = $this->expression($argumentStart, $j, $depth + 1);
                        $argumentStart = $j + 1;
                    } elseif (isset($this->pairs[$j])) {
                        $j = $this->pairs[$j];
                    }
                }
                $input = array_reduce($arguments, static fn ($all, $part) => $all | $part, 0);
                $this->inspectCall($name, $arguments, $input, $line, $this->tokens[$i][3]);
                if (in_array($name, ['base64_decode', 'gzinflate', 'gzuncompress', 'gzdecode', 'str_rot13', 'hex2bin'], true)) {
                    $input |= self::DECODED;
                }
                if ($name === 'filter_input') {
                    $input |= self::REQUEST;
                }
                if (in_array($name, ['wp_remote_get', 'wp_safe_remote_get', 'curl_exec'], true) ||
                    ($name === 'file_get_contents' && ($input & (self::URL | self::REQUEST)))) {
                    $input |= self::REMOTE;
                }
                if (in_array($name, ['escapeshellarg', 'escapeshellcmd'], true)) {
                    $input = 0;
                }
                $flags |= $input;
                $i = min($close, $end - 1);
            } elseif ($id === T_VARIABLE) {
                $flags |= in_array($text, ['$_GET', '$_POST', '$_REQUEST', '$_COOKIE', '$_FILES', '$_SERVER'], true)
                    ? self::REQUEST : ($this->variables[$text] ?? 0);
            } elseif ($id === T_CONSTANT_ENCAPSED_STRING || $id === T_ENCAPSED_AND_WHITESPACE) {
                if (preg_match('/<\?(?:php|=)/i', $text)) {
                    $flags |= self::PHP_CODE;
                }
                if (preg_match('~https?://~i', $text)) {
                    $flags |= self::URL;
                }
                if (preg_match('/\.(?:php[0-9]?|phtml|phar|pht)(?:[\x27\x22]|$)/i', $text)) {
                    $flags |= self::PHP_TARGET;
                }
            } elseif (in_array($text, ['ABSPATH', '__DIR__', '__FILE__'], true) ||
                ($id === T_STRING && preg_match('/^[A-Z_][A-Z0-9_]*(?:_PATH|_DIR|_ROOT)$/D', $text))) {
                $flags |= self::FIXED_BASE;
            } elseif (isset($this->pairs[$i])) {
                $close = min($this->pairs[$i], $end);
                $flags |= $this->expression($i + 1, $close, $depth + 1);
                $i = $close;
            }
        }
        return $flags;
    }

    private function inspectCall(string $name, array $arguments, int $input, int $line, int $offset): void
    {
        $dynamic = str_starts_with($name, '$') ? ($this->variables[$name] ?? 0) : 0;
        $execution = in_array($name, ['eval', 'assert', 'include', 'shell_exec', 'passthru', 'system', 'exec', 'popen', 'proc_open'], true);
        foreach ($this->rules as $rule) {
            $type = $rule['type'];
            $matched = false;
            $label = 'Suspicious PHP data flow';
            if ($type === 'php_request_execution' && (($execution && ($input & self::REQUEST)) || ($dynamic & self::REQUEST))) {
                $matched = true;
                if (in_array($name, ['shell_exec', 'passthru', 'system', 'exec'], true)) {
                    $label = 'Suspicious code signature: request passed to shell';
                }
            } elseif ($type === 'php_decoded_execution' &&
                ((in_array($name, ['eval', 'assert', 'include'], true) && ($input & self::DECODED)) || ($dynamic & self::DECODED))) {
                $matched = true;
                $label = 'Suspicious code signature: obfuscated execution';
            } elseif ($type === 'php_loader_write' && in_array($name, ['file_put_contents', 'fwrite', 'fputs'], true)) {
                $target = $arguments[0] ?? 0;
                $payload = $arguments[1] ?? 0;
                $matched = (bool) (($payload & (self::REQUEST | self::REMOTE | self::DECODED)) &&
                    (($target & self::PHP_TARGET) || ($payload & self::PHP_CODE) ||
                        (($payload & self::DECODED) && ($payload & self::REQUEST))));
                $label = 'Possible PHP loader write';
            }
            if ($matched && count($this->hits) < 100) {
                $fixedInclude = $name === 'include' && ($input & self::FIXED_BASE);
                $this->hits[$rule['id'] . ':' . $line] = [
                    'finding' => $label, 'rule_id' => $rule['id'],
                    'reason' => $fixedInclude ? 'Request-selected include under a fixed base path' : $rule['title'],
                    'line' => $line, 'confidence' => $fixedInclude ? 'low' : $rule['confidence'],
                    'offset' => $offset,
                ];
            } elseif ($matched && !isset($this->hits[$rule['id'] . ':' . $line])) {
                $this->limited = true;
            }
        }
    }

}
