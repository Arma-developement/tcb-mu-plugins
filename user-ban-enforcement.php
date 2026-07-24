<?php
/**
 * Plugin Name: User Ban Enforcement
 * Description: Invalidates all WordPress sessions when the banned role is assigned.
 * Version: 1.0.0
 */

defined('ABSPATH') || exit;

/**
 * Destroy all sessions when the banned role is assigned to a user.
 *
 * This covers roles assigned through both WP_User::set_role()
 * and WP_User::add_role().
 *
 * @param int    $user_id User ID.
 * @param string $role    Internal role slug.
 */
function t3cb_destroy_sessions_when_banned($user_id, $role)
{
    if ($role !== 'banned') {
        return;
    }

    $user_id = absint($user_id);

    if ($user_id === 0) {
        return;
    }

    WP_Session_Tokens::get_instance($user_id)->destroy_all();
}

add_action(
    'add_user_role',
    't3cb_destroy_sessions_when_banned',
    10,
    2
);

