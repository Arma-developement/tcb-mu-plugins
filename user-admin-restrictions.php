<?php
/**
 * Plugin Name: 3CB User Admin Restrictions
 * Description: Blocks non-administrators from wp-admin screens that the 3cb24 theme only hides from
 *   the menu. In mu-plugins so it applies regardless of the active theme and cannot be deactivated
 *   from the admin UI.
 *
 * The theme's prefix_remove_comments_tl() removes these menu links with remove_menu_page(), which
 * hides them but leaves the screens reachable by direct URL. WordPress capabilities already block
 * low-privilege roster roles, but the `editor` role -- granted onto member+ accounts for backend
 * work -- holds edit_others_posts / edit_pages / moderate_comments, so it can open tools.php, the
 * roster CPT lists and comments by URL. This plugin closes those paths.
 *
 * Role model: administrators are dedicated standalone accounts; `editor` is the backend-access grant
 * (keeps the dashboard, Posts, Pages and Media); every other role is a roster member.
 *
 *   Screen                        Allowed                  Denied with
 *   profile.php                   administrators           redirect to front-end profile editor
 *   dashboard (index.php)         administrators, editors  403
 *   tools.php, roster CPT lists   administrators           403
 *   edit-comments.php             administrators, officers 403
 *
 * Refs: WEB-037 (backend screens reachable by URL). WEB-038 (profile-field tampering) -- the
 * profile.php block is defense in depth; the primary fix is a server-side ACF field allowlist.
 *
 * @package tcb-admin-access
 */

defined( 'ABSPATH' ) || exit;

/**
 * profile.php: administrators only; everyone else is redirected to the front-end profile editor
 * ([tcbp_public_edit_profile] on /edit-user-profile), where they change their own details. The
 * screen renders ACF fields that drive backend behaviour (service_record, steam_info, discord_id,
 * application, ...) which non-admins must not edit. load-profile.php fires for both the GET view and
 * the POST save. Falls back to the home page if the front-end page is gone.
 */
function tcb_admin_access_block_profile() {
	if ( in_array( 'administrator', (array) wp_get_current_user()->roles, true ) ) {
		return;
	}
	$fe_profile = get_page_by_path( 'edit-user-profile' );
	wp_safe_redirect( $fe_profile ? get_permalink( $fe_profile ) : home_url() );
	exit;
}
add_action( 'load-profile.php', 'tcb_admin_access_block_profile' );

/**
 * Deny the current admin screen the way core does for a missing capability (see
 * wp-admin/includes/menu.php): fire admin_page_access_denied, then wp_die() with core's own message
 * and a 403. Renders the standard WordPress error page.
 */
function tcb_admin_access_deny() {
	/** This action is documented in wp-admin/includes/menu.php */
	do_action( 'admin_page_access_denied' );
	wp_die( __( 'Sorry, you are not allowed to access this page.' ), 403 );
}

/**
 * Dashboard (index.php): administrators and editors. Every role holds `read`, so WordPress lets any
 * logged-in user load the dashboard -- the theme only hid the menu link. Editors keep it as their
 * backend-access grant; other roles are denied.
 */
function tcb_admin_access_block_dashboard() {
	if ( array_intersect( array( 'administrator', 'editor' ), (array) wp_get_current_user()->roles ) ) {
		return;
	}
	tcb_admin_access_deny();
}
add_action( 'load-index.php', 'tcb_admin_access_block_dashboard' );

/**
 * tools.php, the roster CPT lists (service-record / application / report / loa) and edit-comments.php.
 * Administrators pass; officers also keep Comments, which they moderate. load-edit.php is shared by
 * Posts, Pages and every post type, so only the four roster CPTs are matched by post_type -- Posts,
 * Pages and other types fall through to WordPress's own capability checks.
 */
function tcb_admin_access_block_restricted_screen() {
	$roles = (array) wp_get_current_user()->roles;
	if ( in_array( 'administrator', $roles, true ) ) {
		return;
	}

	global $pagenow;

	// Officers moderate comments.
	if ( 'edit-comments.php' === $pagenow && in_array( 'officer', $roles, true ) ) {
		return;
	}

	// Shared hook: only the roster CPT list screens are ours to block.
	if ( 'edit.php' === $pagenow ) {
		$blocked_types = array( 'service-record', 'application', 'report', 'loa' );
		$post_type     = isset( $_GET['post_type'] ) ? sanitize_key( wp_unslash( $_GET['post_type'] ) ) : 'post';
		if ( ! in_array( $post_type, $blocked_types, true ) ) {
			return;
		}
	}

	tcb_admin_access_deny();
}
add_action( 'load-tools.php', 'tcb_admin_access_block_restricted_screen' );
add_action( 'load-edit.php', 'tcb_admin_access_block_restricted_screen' );
add_action( 'load-edit-comments.php', 'tcb_admin_access_block_restricted_screen' );

/**
 * Considered and intentionally left open to editors:
 *
 *  - Simple History log: scopes each row by the originating logger's capability. The sensitive
 *    loggers (user/login = edit_users; settings/updates/plugins/themes = manage_options /
 *    activate_plugins / edit_theme_options) sit above an editor, so an editor sees only content-scope
 *    entries they already have access to. No block needed.
 *
 *  - tribe_events (missions): editors manage mission events -- the reason the role is granted.
 *
 *  - epkb_post_type_1 (wiki): editors can edit all articles via wp-admin, bypassing the theme's
 *    front-end category-role restrictions. Left open for now; to block, add its post_type to the
 *    load-edit.php guard above (it shares edit_others_posts, so a screen block is the only option).
 */
