<?php
// Local release lab callback. Never loaded in a regular WordPress installation.
if (!defined('SD_RELEASE_LAB') || SD_RELEASE_LAB !== true) {
    return;
}

add_filter('pre_wp_mail', '__return_true');
add_action('woocommerce_api_sd_release_payment', static function (): void {
    $body = file_get_contents('php://input');
    $signature = $_SERVER['HTTP_X_SD_RELEASE_SIGNATURE'] ?? '';
    if (!hash_equals(hash_hmac('sha256', $body, 'site-defense-local-release-fixture'), $signature)) {
        wp_send_json(['paid' => false], 401);
    }
    $data = json_decode($body, true);
    $order = wc_get_order((int) ($data['order_id'] ?? 0));
    if (!$order || $order->get_billing_email() !== 'sd-release@example.test') {
        wp_send_json(['paid' => false], 404);
    }
    if (!$order->get_transaction_id()) {
        $order->payment_complete('release-local-transaction');
    }
    wp_send_json(['paid' => $order->is_paid(), 'transaction' => $order->get_transaction_id()]);
});
