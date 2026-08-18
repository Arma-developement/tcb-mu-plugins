<?php
/**
 * Plugin Name: Return To Origin After Login
 * Description: Returns members to the page they originally requested after logging in through Nextend Steam SSO.
 */

defined('ABSPATH') || exit;

const T3CB_RETURN_COOKIE = '__Host-3cb_login_return';

/**
 * Reduce a candidate to a safe same-site relative path, or '' when it is not one.
 * Auth endpoints and query strings are dropped.
 *
 * @param mixed $raw Candidate value.
 *
 * @return string Sanitized relative path, or ''.
 */
function t3cb_sanitize_return_path($raw)
{
    if (!is_string($raw) || $raw === '' || strlen($raw) > 700) {
        return '';
    }

    if ($raw[0] !== '/' || (isset($raw[1]) && ($raw[1] === '/' || $raw[1] === '\\'))) {
        return '';
    }

    foreach (array($raw, rawurldecode($raw)) as $candidate) {
        if (strpbrk($candidate, "\r\n\0") !== false
            || strpos($candidate, '\\') !== false
            || preg_match('#[^\x20-\x7E]#', $candidate)) {
            return '';
        }
    }

    $path         = untrailingslashit((string) (wp_parse_url($raw, PHP_URL_PATH) ?: ''));
    $decoded_path = $path;

    for ($i = 0; $i < 5; $i++) {
        $next = rawurldecode($decoded_path);

        if ($next === $decoded_path) {
            break;
        }

        $decoded_path = $next;
    }

    if (rawurldecode($decoded_path) !== $decoded_path) {
        return '';
    }

    if ($decoded_path !== '' && ($decoded_path[0] !== '/'
        || (isset($decoded_path[1]) && $decoded_path[1] === '/')
        || strpos($decoded_path, '\\') !== false
        || strpbrk($decoded_path, "\r\n\0") !== false
        || preg_match('#[^\x20-\x7E]#', $decoded_path)
        || preg_match('#(?:^|/)\.\.?(?:/|$)#', $decoded_path))) {
        return '';
    }

    foreach (array(home_url('/login'), wp_login_url(), site_url('/wp-login.php'), admin_url()) as $deny_url) {
        $deny = untrailingslashit((string) (wp_parse_url($deny_url, PHP_URL_PATH) ?: ''));

        if ($deny !== '' && ($decoded_path === $deny || strpos($decoded_path, $deny . '/') === 0)) {
            return '';
        }
    }

    return $path === '' ? '/' : $path;
}

/**
 * Remember the originally requested path when a guest is redirected to the login page.
 * Only redirects to this site's own login page set the cookie.
 */
add_filter(
    'wp_redirect',
    function ($location) {
        if (is_user_logged_in() || is_admin() || wp_doing_ajax() || (defined('REST_REQUEST') && REST_REQUEST) || headers_sent()) {
            return $location;
        }

        $loc   = (string) $location;
        $home  = wp_parse_url(home_url());
        $parts = wp_parse_url($loc);

        if ($parts === false) {
            return $location;
        }

        if (isset($parts['scheme']) || isset($parts['host'])) {
            $defaults   = array('https' => 443, 'http' => 80);
            $home_port  = $home['port'] ?? $defaults[strtolower($home['scheme'] ?? 'https')] ?? null;
            $parts_port = $parts['port'] ?? $defaults[strtolower($parts['scheme'] ?? '')] ?? null;

            if (!isset($parts['scheme'], $parts['host'])
                || strcasecmp($parts['scheme'], $home['scheme'] ?? 'https') !== 0
                || strcasecmp($parts['host'], $home['host'] ?? '') !== 0
                || $parts_port !== $home_port) {
                return $location;
            }
        } elseif (!isset($loc[0]) || $loc[0] !== '/' || (isset($loc[1]) && $loc[1] === '/')) {
            return $location;
        }

        $login_path = untrailingslashit((string) (wp_parse_url(home_url('/login'), PHP_URL_PATH) ?: '/login'));

        if (untrailingslashit((string) ($parts['path'] ?? '')) !== $login_path) {
            return $location;
        }

        $current = t3cb_sanitize_return_path($_SERVER['REQUEST_URI'] ?? '');

        if ($current !== '') {
            setcookie(T3CB_RETURN_COOKIE, $current, array(
                'expires'  => time() + 15 * MINUTE_IN_SECONDS,
                'path'     => '/',
                'secure'   => true,
                'httponly' => true,
                'samesite' => 'Lax',
            ));
        }

        return $location;
    },
    10,
    1
);

/**
 * Redirect to the stored target after a Steam login. The cookie is one-shot;
 * without one Nextend's configured redirect applies.
 *
 * @param string $redirect_to           Redirect URL chosen by Nextend.
 * @param string $requested_redirect_to Redirect URL requested by the flow.
 *
 * @return string
 */
function t3cb_return_redirect($redirect_to, $requested_redirect_to)
{
    if (empty($_COOKIE[T3CB_RETURN_COOKIE])) {
        return $redirect_to;
    }

    $cookie = wp_unslash((string) $_COOKIE[T3CB_RETURN_COOKIE]);
    unset($_COOKIE[T3CB_RETURN_COOKIE]);

    $path = t3cb_sanitize_return_path($cookie);

    if (!headers_sent()) {
        setcookie(T3CB_RETURN_COOKIE, '', array(
            'expires'  => time() - YEAR_IN_SECONDS,
            'path'     => '/',
            'secure'   => true,
            'httponly' => true,
            'samesite' => 'Lax',
        ));
    }

    $fallback = wp_validate_redirect((string) $redirect_to, home_url('/'));

    if ($path === '') {
        return $fallback;
    }

    return wp_validate_redirect(home_url($path), $fallback);
}

add_filter('nsl_steamlast_location_redirect', 't3cb_return_redirect', 20, 2);
add_filter('nsl_steamdefault_last_location_redirect', 't3cb_return_redirect', 20, 2);
