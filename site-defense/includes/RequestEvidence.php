<?php
namespace SiteDefense;

// Also loaded before WordPress by the early firewall.
final class RequestEvidence
{
    public static function id($value): string
    {
        return is_string($value) && preg_match('/^[A-Za-z0-9][A-Za-z0-9_.-]{7,127}$/D', $value) ? $value : '';
    }

    public static function method($value): string
    {
        return is_string($value) && preg_match('/^[A-Z]{1,16}$/D', $value) ? $value : '';
    }

    public static function path($value): string
    {
        return is_string($value) && preg_match('~^/?[a-zA-Z0-9._/-]{1,220}$~D', $value) &&
            !preg_match('~(?:^|/)\.{1,2}(?:/|$)|^//~', $value) ? $value : '';
    }

    public static function requestPath($value): string
    {
        return is_string($value) && str_starts_with($value, '/') ? self::path(explode('?', $value, 2)[0]) : '';
    }

    public static function capture(array $server, string $layer): array
    {
        return self::wafContext([
            'route' => self::requestPath($server['REQUEST_URI'] ?? null),
            'method' => $server['REQUEST_METHOD'] ?? null,
            // Set by the server/FastCGI configuration. Client HTTP headers have the HTTP_ prefix.
            'request_id' => $server['SITE_DEFENSE_REQUEST_ID'] ?? null,
            'layer' => $layer,
        ]);
    }

    public static function wafContext(array $context): array
    {
        return [
            'route' => self::requestPath($context['route'] ?? null),
            'method' => self::method($context['method'] ?? null),
            'request_id' => self::id($context['request_id'] ?? null),
            'layer' => in_array($context['layer'] ?? null, ['early', 'wordpress'], true) ? $context['layer'] : '',
        ];
    }

    public static function isWaf(string $kind): bool
    {
        return $kind === 'waf_block' || $kind === 'waf_observe';
    }
}
