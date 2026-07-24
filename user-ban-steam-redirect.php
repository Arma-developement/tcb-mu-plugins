<?php
/**
 * Plugin Name: Steam User Bans
 * Description: Blocks banned WordPress users from logging in through Nextend Steam SSO.
 */

defined('ABSPATH') || exit;

/**
 * Record, within a request, that a Steam login was denied because the account is
 * banned, so the message and redirect filters below can respond specifically
 * without leaning on a request global. Call with true from the login-gate filter;
 * call with no argument to read the flag.
 */
function t3cb_steam_ban_denied($mark = false)
{
    static $denied = false;

    if ($mark) {
        $denied = true;
    }

    return $denied;
}

add_filter(
    'nsl_steam_is_login_allowed',
    function ($allowed, $provider, $user_id) {
        $user = get_userdata((int) $user_id);

        if ($user && in_array('banned', (array) $user->roles, true)) {
            t3cb_steam_ban_denied(true);

            return false;
        }

        return $allowed;
    },
    10,
    3
);

add_filter('nsl_disabled_login_error_message', function ($message) {
    if (t3cb_steam_ban_denied()) {
        return 'Your account has been banned and cannot access this website.';
    }

    return $message;
});

add_filter('nsl_disabled_login_redirect_url', function ($url) {
    if (t3cb_steam_ban_denied()) {
        return home_url('/banned-account/');
    }

    return $url;
});

