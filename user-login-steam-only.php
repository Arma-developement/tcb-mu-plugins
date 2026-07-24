<?php
/**
 * Plugin Name: Steam-only login
 * Description: Steam authentication and Steam ID profile synchronization.
 */

defined('ABSPATH') || exit;

/**
 * Get the SteamID64 connected to a WordPress user by Nextend.
 */
if (!function_exists('t3cb_nsl_get_steam_id')) {
    function t3cb_nsl_get_steam_id($user_id)
    {
        global $wpdb;

        $user_id = absint($user_id);

        if ($user_id === 0) {
            return '';
        }

        $table = $wpdb->prefix . 'social_users';

        $steam_id = $wpdb->get_var(
            $wpdb->prepare(
                "SELECT identifier
                 FROM {$table}
                 WHERE ID = %d
                   AND type = %s
                 LIMIT 1",
                $user_id,
                'steam'
            )
        );

        $steam_id = is_string($steam_id) ? trim($steam_id) : '';

        if ($steam_id === '' || !preg_match('/^[0-9]+$/', $steam_id)) {
            return '';
        }

        return $steam_id;
    }
}

/**
 * Copy the Nextend Steam ID into user meta.
 */
if (!function_exists('t3cb_sync_profile_steam_id')) {
    function t3cb_sync_profile_steam_id($user_id)
    {
        $user_id  = absint($user_id);
        $steam_id = t3cb_nsl_get_steam_id($user_id);

        if ($steam_id === '') {
            return;
        }

        if (get_user_meta($user_id, 'steam_id', true) !== $steam_id) {
            update_user_meta($user_id, 'steam_id', $steam_id);
        }
    }
}

add_action(
    'nsl_steam_login',
    function ($user_id) {
        t3cb_sync_profile_steam_id($user_id);
    },
    20,
    1
);

add_action(
    'nsl_steam_link_user',
    function ($user_id) {
        t3cb_sync_profile_steam_id($user_id);
    },
    20,
       1
);

add_action(
    'init',
    function () {
        if (!is_user_logged_in()) {
            return;
        }

        $user_id = get_current_user_id();

        // The administrator authenticates by password and has no Nextend link,
        // so this re-sync would query wp_social_users on every request without
        // ever populating the meta. Skip it.
        if (user_can($user_id, 'manage_options')) {
            return;
        }

        if (get_user_meta($user_id, 'steam_id', true) === '') {
            t3cb_sync_profile_steam_id($user_id);
        }
    }
);

add_action(
    'nsl_unlink_user',
    function ($user_id, $provider_id) {
        if ($provider_id === 'steam') {
            delete_user_meta(absint($user_id), 'steam_id');
        }
    },
    10,
    2
);

/**
 * Enforce Steam-only authentication.
 *
 * Runs after the core credential callbacks (priority 20) resolve a user, so it
 * governs every path that flows through wp_authenticate(): the login form,
 * username/email login, application passwords, and XML-RPC. The Steam SSO path
 * does not call wp_authenticate() (Nextend logs users in via wp_set_current_user()
 * + wp_set_auth_cookie()), so this filter never runs for a Steam login.
 *
 * Only the site administrator (manage_options) may authenticate with a WordPress
 * password; every member must use Steam. The banned role is rejected on all
 * credential paths, complementing the Steam-SSO-only ban gate in
 * user-ban-steam-redirect.php.
 */
add_filter(
    'authenticate',
    function ($user, $username, $password) {
        if (!($user instanceof WP_User)) {
            return $user;
        }

        if (in_array('banned', (array) $user->roles, true)) {
            return new WP_Error(
                't3cb_account_banned',
                'Your account has been banned and cannot access this website.'
            );
        }

        if (!user_can($user, 'manage_options')) {
            return new WP_Error(
                't3cb_steam_only_login',
                'This account must sign in with Steam.'
            );
        }

        return $user;
    },
    30,
    3
);

/**
 * Disable the lost-password / reset flow for non-administrators.
 *
 * Members have no user-known password (Steam sets a random one), so the reset
 * flow is the actual vector by which a banned member could regain access. No
 * reset key or email is issued for any account except the site administrator.
 */
add_filter(
    'allow_password_reset',
    function ($allow, $user_id) {
        $user = get_userdata($user_id);

        if ($user && !user_can($user, 'manage_options')) {
            return false;
        }

        return $allow;
    },
    10,
    2
);

