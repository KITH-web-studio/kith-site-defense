<?php
namespace SiteDefense;

defined('ABSPATH') || exit;

final class StoredHtml extends \WP_HTML_Processor
{
    public const MAX_BYTES = 131072;
    private const MAX_FRAGMENTS = 12;

    public static function fragments(string $html): array
    {
        $prefix = ltrim($html);
        if ($prefix === '' || strlen($html) > self::MAX_BYTES || str_contains($html, "\0") ||
            !preg_match('//u', $html) || is_serialized($prefix, false) || preg_match('/^[aOCESs]:\d+:/', $prefix) ||
            str_starts_with($prefix, '{') || (str_starts_with($prefix, '"') && is_string(json_decode($prefix, true, 32))) ||
            preg_match('/^\[\s*(?:[\[\]{"0-9-]|true\b|false\b|null\b)/', $prefix)) {
            return [];
        }
        $processor = self::create_fragment($html);
        if (!$processor) {
            return [];
        }
        $found = [];
        while ($processor->next_tag()) {
            $tag = $processor->get_tag();
            if (($tag !== 'SCRIPT' && $tag !== 'META') || $processor->get_namespace() !== 'html' ||
                array_intersect(['TEMPLATE', 'NOSCRIPT'], $processor->get_breadcrumbs())) {
                continue;
            }
            $kind = $processor->removalKind($tag);
            if ($kind === '' || !$processor->set_bookmark('sd_fragment')) {
                continue;
            }
            // WP_HTML_Processor bookmarks refer to the full token, including the SCRIPT end tag.
            $span = $processor->bookmarks['_sd_fragment'];
            $processor->release_bookmark('sd_fragment');
            $bytes = substr($html, $span->start, $span->length);
            if ($tag === 'SCRIPT' && !preg_match('~</script(?:[\t\n\f\r /][^>]*)?>\z~i', $bytes)) {
                continue;
            }
            if (count($found) < self::MAX_FRAGMENTS) {
                $found[] = ['kind' => $kind, 'line' => 1 + substr_count($html, "\n", 0, $span->start),
                    'offset' => $span->start, 'bytes' => $span->length, 'sha256' => hash('sha256', $bytes)];
            }
        }
        return $processor->get_last_error() || $processor->paused_at_incomplete_token() ? [] : $found;
    }

    private function removalKind(string $tag): string
    {
        if ($tag === 'META') {
            $equiv = $this->get_attribute('http-equiv');
            $content = $this->get_attribute('content');
            return is_string($equiv) && strcasecmp(trim($equiv), 'refresh') === 0 && is_string($content) &&
                preg_match('~^\s*\d+(?:\.\d+)?\s*[;,]\s*url\s*=\s*\S~i', $content) ? 'meta_refresh' : '';
        }
        $type = $this->get_attribute('type');
        if ($type === null && is_string($language = $this->get_attribute('language')) && trim($language) !== '') {
            $type = 'text/' . $language;
        }
        $type = is_string($type) ? strtolower(trim($type)) : '';
        return $type === '' || $type === 'module' || preg_match(
            '~^(?:application/(?:x-)?(?:java|ecma)script|text/(?:(?:x-)?(?:java|ecma)script|javascript1\.[0-5]|jscript|livescript))$~D', $type
        ) ? 'script' : '';
    }

    public static function remove(string $html, array $fragments): ?string
    {
        if (!$fragments || count($fragments) > self::MAX_FRAGMENTS) {
            return null;
        }
        $position = 0;
        $replacement = '';
        foreach ($fragments as $fragment) {
            $offset = $fragment['offset'] ?? -1;
            $length = $fragment['bytes'] ?? 0;
            if (!is_int($offset) || !is_int($length) || $offset < $position || $length < 1 ||
                $length > strlen($html) - $offset || hash('sha256', substr($html, $offset, $length)) !== ($fragment['sha256'] ?? null)) {
                return null;
            }
            // Preserve the boundary so formerly separated characters cannot form a new tag or shortcode.
            $replacement .= substr($html, $position, $offset - $position) . '<!---->';
            $position = $offset + $length;
        }
        return $replacement . substr($html, $position);
    }
}
