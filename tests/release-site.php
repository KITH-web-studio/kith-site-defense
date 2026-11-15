<?php
// Invoked by tools/release.py on disposable WordPress installations.
if (!defined('SD_RELEASE_LAB') || SD_RELEASE_LAB !== true || wp_get_environment_type() !== 'local') {
    throw new RuntimeException('A disposable WordPress release lab is required.');
}

global $wpdb;
$key = 'sd_release_fixture';
$state = get_option($key, []);
$action = $args[0] ?? '';
$write = static function (array $changes) use (&$state, $key): void {
    $state = $changes + $state;
    update_option($key, $state, false);
};
$require = static function ($result) {
    if (is_wp_error($result)) {
        throw new RuntimeException($result->get_error_message());
    }
    return $result;
};

switch ($action) {
    case 'environment':
        $hpos = defined('WC_VERSION') && \Automattic\WooCommerce\Utilities\OrderUtil::custom_orders_table_usage_is_enabled();
        echo wp_json_encode(['wp' => get_bloginfo('version'), 'php' => PHP_VERSION, 'home' => home_url(),
            'plugins' => array_values(get_option('active_plugins', [])), 'sodium' => extension_loaded('sodium'),
            'woocommerce' => defined('WC_VERSION') ? WC_VERSION : null, 'hpos' => $hpos]);
        break;

    case 'setup':
        if ($state) {
            throw new RuntimeException('Existing release fixture. Run restore on this lab before starting again.');
        }
        $write(['version_marker' => wp_generate_uuid4(), 'audit' => get_option('sd_db_audit', null),
            'scan' => get_option('sd_scan', null), 'settings' => get_option('sd_settings', null),
            'feed' => get_option('sd_vulnerability_db', null), 'feed_status' => get_option('sd_feed_status', null),
            'login' => get_option('sd_login_route', null), 'alerts' => get_option('sd_alerts', null),
            'firewall' => get_option('sd_firewall', null),
            'email' => 'sd-release@example.test']);
        $login = 'sd-release-' . substr($state['version_marker'], 0, 8);
        $password = wp_generate_password(28, false);
        $user = $require(wp_insert_user(['user_login' => $login, 'user_pass' => $password, 'role' => 'subscriber']));
        (new WP_User($user))->add_cap('site_defense_investigate');
        $write(['user' => $user, 'login_name' => $login, 'password' => $password]);
        $post = $require(wp_insert_post(['post_title' => 'Site Defense release fixture', 'post_status' => 'draft'], true));
        $write(['post' => $post, 'original' => "<p>Release &amp; 100% \u{1F9EA}</p>\r\n<script>void('sd-release-private')</script><p>Tail</p>"]);
        $wpdb->update($wpdb->posts, ['post_content' => $state['original']], ['ID' => $post]);
        clean_post_cache($post);

        $uploads = wp_upload_dir();
        $file = trailingslashit($uploads['basedir']) . 'sd-release-inert.php';
        if ($uploads['error'] || file_exists($file) || is_link($file)) {
            throw new RuntimeException('The upload fixture cannot be created.');
        }
        $write(['file' => wp_normalize_path($file), 'url' => trailingslashit($uploads['baseurl']) . basename($file)]);
        file_put_contents($file, '<?php echo "site-defense-release-inert";');
        $relative = \SiteDefense\Scanner::relativePath($file);
        $scan = (array) $state['scan'];
        $scan['findings'][] = ['Executable file in uploads', $relative, hash_file('sha256', $file)];
        update_option('sd_scan', $scan, false);
        $write(['relative' => $relative, 'original_hash' => hash('sha256', $state['original'])]);

        if (defined('WC_VERSION')) {
            if (!\Automattic\WooCommerce\Utilities\OrderUtil::custom_orders_table_usage_is_enabled()) {
                throw new RuntimeException('HPOS needs to be enabled in the release lab.');
            }
            WC_Install::create_pages();
            $checkout = wc_get_page_id('checkout');
            $write(['checkout' => $checkout, 'checkout_original' => get_post_field('post_content', $checkout, 'raw'),
                'cod' => get_option('woocommerce_cod_settings', null)]);
            $block = (new ReflectionMethod(WC_Install::class, 'get_checkout_block_content'))->invoke(null);
            $require(wp_update_post(['ID' => $checkout, 'post_content' => wp_slash($block)], true));
            update_option('woocommerce_cod_settings', ['enabled' => 'yes', 'enable_for_virtual' => 'yes']);
            $product = new WC_Product_Simple();
            $product->set_name('Site Defense release product');
            $product->set_status('publish');
            $product->set_virtual(true);
            $product->set_regular_price('14.50');
            $write(['product' => $product->save()]);
            $payment = WPMU_PLUGIN_DIR . '/sd-release-payment.php';
            if (file_exists($payment) || !wp_mkdir_p(WPMU_PLUGIN_DIR)) {
                throw new RuntimeException('The payment fixture cannot be created.');
            }
            $write(['payment' => $payment]);
            if (!copy($args[1], $payment)) {
                throw new RuntimeException('The payment fixture could not be copied.');
            }
        }
        echo wp_json_encode(array_intersect_key($state, array_flip(['version_marker', 'user', 'login_name', 'password',
            'post', 'url', 'relative', 'original_hash', 'checkout', 'product'])));
        break;

    case 'content':
        echo hash('sha256', (string) get_post_field('post_content', $state['post'], 'raw'));
        break;

    case 'drift':
        $wpdb->update($wpdb->posts, ['post_content' => $state['original'] . (($args[1] ?? '') === 'restore' ? '' : '!')], ['ID' => $state['post']]);
        clean_post_cache($state['post']);
        break;

    case 'stage':
        $option = \SiteDefense\CleanupPlan::PREFIX . $args[1];
        $plan = get_option($option);
        $plan['steps'][$args[2]]['state'] = $args[3];
        update_option($option, $plan, false);
        break;

    case 'alerts':
        $settings = \SiteDefense\State::settings();
        $channels = [];
        $settings['notify'] = true;
        $settings['email'] = $state['email'];
        update_option('sd_settings', $settings);
        \SiteDefense\Alerts::save(['telegram' => '1', 'telegram_token' => '123456:local_test_token_abcdefgh', 'telegram_chat' => '12345']);
        add_filter('pre_wp_mail', static function ($return, $mail) use ($state, &$channels) {
            if (in_array($state['email'], (array) $mail['to'], true)) {
                $channels[] = 'email';
            }
            return true;
        }, 10, 2);
        add_filter('pre_http_request', static function ($return, $request, $url) use (&$channels) {
            if (wp_parse_url($url, PHP_URL_HOST) === 'api.telegram.org') {
                $channels[] = 'telegram';
            }
            return ['response' => ['code' => 200], 'body' => '{"ok":true}'];
        }, 10, 3);
        \SiteDefense\Alerts::test();
        update_option('sd_settings', $state['settings'] ?? \SiteDefense\State::DEFAULTS);
        if ($state['alerts'] === null) {
            delete_option('sd_alerts');
        } else {
            update_option('sd_alerts', $state['alerts']);
        }
        echo wp_json_encode($channels);
        break;

    case 'order':
        $id = (int) $args[1];
        $order = wc_get_order($id);
        if (($args[2] ?? '') === 'pending') {
            $order->update_status('pending');
        }
        $rows = [];
        foreach (['wc_orders' => 'id', 'wc_order_addresses' => 'order_id', 'wc_order_operational_data' => 'order_id',
            'wc_orders_meta' => 'order_id', 'woocommerce_order_items' => 'order_id'] as $table => $column) {
            $rows[$table] = $wpdb->get_results($wpdb->prepare(
                "SELECT * FROM {$wpdb->prefix}$table WHERE $column=%d ORDER BY 1", $id
            ), ARRAY_A);
        }
        echo wp_json_encode(['status' => $order->get_status(), 'transaction' => $order->get_transaction_id(), 'rows' => $rows]);
        break;

    case 'restore':
        if (!$state) {
            break;
        }
        foreach (array_slice($args, 1) as $value) {
            if (str_starts_with($value, 'order:') && defined('WC_VERSION')) {
                $order = wc_get_order((int) substr($value, 6));
                if ($order) {
                    $order->delete(true);
                }
            } elseif (preg_match('/^[a-f0-9]{32}$/D', $value)) {
                delete_option(\SiteDefense\CleanupPlan::PREFIX . $value);
            }
        }
        if (defined('WC_VERSION') && isset($state['checkout'])) {
            wp_update_post(['ID' => $state['checkout'], 'post_content' => wp_slash($state['checkout_original'])]);
            if ($state['cod'] === null) {
                delete_option('woocommerce_cod_settings');
            } else {
                update_option('woocommerce_cod_settings', $state['cod']);
            }
        }
        foreach (['file', 'payment'] as $field) {
            if (!empty($state[$field]) && is_file($state[$field])) {
                unlink($state[$field]);
            }
        }
        foreach (['post', 'product'] as $field) {
            if (!empty($state[$field])) {
                wp_delete_post($state[$field], true);
            }
        }
        if (!empty($state['user'])) {
            require_once ABSPATH . 'wp-admin/includes/user.php';
            wp_delete_user($state['user']);
        }
        foreach (['audit' => 'sd_db_audit', 'scan' => 'sd_scan', 'settings' => 'sd_settings', 'login' => 'sd_login_route',
            'feed' => 'sd_vulnerability_db', 'feed_status' => 'sd_feed_status', 'alerts' => 'sd_alerts',
            'firewall' => 'sd_firewall'] as $field => $option) {
            if (($state[$field] ?? null) === null) {
                delete_option($option);
            } else {
                update_option($option, $state[$field], false);
            }
        }
        delete_option($key);
        break;

    default:
        throw new RuntimeException('Unknown release fixture action.');
}
