<?php

/**
 * Plugin Name: Plugin Security Scanner
 * Plugin URI: http://www.glenscott.co.uk/plugin-security-scanner/
 * Description: This plugin determines whether any of your plugins have security vulnerabilities.  It does this by looking up details in the WPScan Vulnerability Database.
 * Version: 1.4.1
 * Author: Glen Scott
 * Author URI: http://www.glenscott.co.uk
 * License: GPL2
 * Text Domain: plugin-security-scanner
 */

/*  Copyright 2015  Glen Scott  (email : glen@glenscott.co.uk)

	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License, version 2, as
	published by the Free Software Foundation.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program; if not, write to the Free Software
	Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

defined( 'ABSPATH' ) or die( 'No script kiddies please!' );

if ( ! class_exists( 'WP_Http' ) ) {
	include_once( ABSPATH . WPINC. '/class-http.php' );
}

// Check if get_plugins() function exists. This is required on the front end of the
// site, since it is in a file that is normally only loaded in the admin.
if ( ! function_exists( 'get_plugins' ) ) {
	require_once ABSPATH . 'wp-admin/includes/plugin.php';
}

add_action( 'admin_menu', 'plugin_security_scanner_menu' );
add_action( 'admin_init', 'plugin_security_scanner_register_settings' );

function plugin_security_scanner_menu() {
	add_management_page( __( 'Plugin Security Scanner', 'plugin-security-scanner' ),
	__( 'Plugin Security Scanner', 'plugin-security-scanner' ), 'manage_options', 'plugin-security-scanner', 'plugin_security_scanner_tools' );
}

function plugin_security_scanner_register_settings() {
	add_settings_section( 'plugin-security-scanner-section', __( 'Plugin Security Scanner', 'plugin-security-scanner' ),
	'plugin_security_scanner_section_text', 'general' );
	add_settings_field( 'plugin-security-scanner-email-notification', __( 'Email Notification', 'plugin-security-scanner' ),
	'plugin_security_scanner_email_notification_field', 'general', 'plugin-security-scanner-section' );

	if ( false === get_option( 'plugin-security-scanner' ) ) {
	    update_option( 'plugin-security-scanner', array( 'email_notification' => '1' ) );
	}

	register_setting( 'general', 'plugin-security-scanner', 'plugin_security_scanner_validate' );
}

function plugin_security_scanner_section_text() {
}

function plugin_security_scanner_validate($input) {
	if ( ! is_array( $input ) ) {
		$input = array(
			'email_notification' => 0,
			);
	}
	return $input;
}

function plugin_security_scanner_email_notification_field() {
	$options = get_option( 'plugin-security-scanner' );

	echo '<input type="checkbox" id="plugin-security-scanner-email-notification" name="plugin-security-scanner[email_notification]" value="1"' . checked( 1, $options['email_notification'], false ) . '/>';
	echo '<label for="plugin-security-scanner-email-notification">Send an e-mail notification when vulnerable plugins are found?</label>';
}

function get_vulnerable_plugins() {
	$vulnerabilities = array();

	$request = new WP_Http;

	foreach ( get_plugins() as $name => $details ) {
		// get unique name
		if ( preg_match( '|(.+)/|', $name, $matches ) ) {
			$plugin_key = $matches[1];
			$result = $request->request( 'https://wpvulndb.com/api/v2/plugins/' . $plugin_key );

			if ( is_wp_error( $result ) ) {
				trigger_error( $result->get_error_message(), E_USER_ERROR );
			}
			else {
				if ( $result['body'] ) {
					$plugin = json_decode( $result['body'] );

					if ( isset( $plugin->$plugin_key->vulnerabilities ) ) {
						foreach ( $plugin->$plugin_key->vulnerabilities as $vuln ) {
							if ( ! isset($vuln->fixed_in) ||
								version_compare( $details['Version'], $vuln->fixed_in, '<' ) ) {
								$vulnerabilities[$name][] = $vuln;
							}
						}
					}
				}
			}
		}
	}

	foreach ( wp_get_themes() as $details ) {
		$theme_key = strtolower( str_replace( ' ', '', $details->name ) );
		$result = $request->request( 'https://wpvulndb.com/api/v2/themes/' . $theme_key );

		if ( is_wp_error( $result ) ) {
			trigger_error( $result->get_error_message(), E_USER_ERROR );
		}
		else {
			if ( $result['body'] ) {
				$theme = json_decode( $result['body'] );

				if ( isset( $theme->$theme_key->vulnerabilities ) ) {
					foreach ( $theme->$theme_key->vulnerabilities as $vuln ) {
						if ( ! isset($vuln->fixed_in) ||
							version_compare( $details['Version'], $vuln->fixed_in, '<' ) ) {
							$vulnerabilities[$theme_key][] = $vuln;
						}
					}
				}
			}
		}
	}

	return $vulnerabilities;
}

function plugin_security_scanner_tools() {
	if ( ! current_user_can( 'manage_options' ) )  {
		wp_die( __( 'You do not have sufficient permissions to access this page.' ) );
	}
	echo '<div class="wrap">';
	echo '<h2>' . esc_html__( 'Plugin Security Scanner', 'plugin-security-scanner' ) . '</h2>';

	$vulnerability_count = 0;

	$vulnerabilities = get_vulnerable_plugins();

	foreach ( $vulnerabilities as $plugin_name => $plugin_vulnerabilities ) {
		foreach ( $plugin_vulnerabilities as $vuln ) {
				echo '<p><strong>' . esc_html__( 'Vulnerability found', 'plugin-security-scanner' ) . ':</strong> ' . esc_html( $vuln->title ) . ' -- <a href="' . esc_url( 'https://wpvulndb.com/vulnerabilities/' . $vuln->id ) . '" target="_blank">' . esc_html__( 'View details', 'plugin-security-scanner' ) . '</a></p>';

					$vulnerability_count++;
		}
		flush();
	}

	echo '<p>' .
		sprintf(
			_n(
				'Scan completed: %s vulnerability found.',
			    'Scan completed: %s vulnerabilities found.',
				$vulnerability_count,
				'plugin-security-scanner'
			),
			'<strong>' . esc_html( $vulnerability_count ) . '</strong>'
		)
	.
		'</p>';

	echo '</div>';
}

// scheduled email to admin
register_activation_hook( __FILE__, 'plugin_security_scanner_activation' );
/**
 * On activation, set a time, frequency and name of an action hook to be scheduled.
 */
function plugin_security_scanner_activation() {
	wp_schedule_event( time(), 'daily', 'plugin_security_scanner_daily_event_hook' );
}

add_action( 'plugin_security_scanner_daily_event_hook', 'plugin_security_scanner_do_this_daily' );
/**
 * On the scheduled action hook, run the function.
 */
function plugin_security_scanner_do_this_daily() {
	$options = get_option( 'plugin-security-scanner' );
	$admin_email = get_option( 'admin_email' );

	if ( $admin_email && '1' === $options['email_notification'] ) {
		$mail_body = '';

		// run scan
		$vulnerability_count = 0;

		$vulnerabilities = get_vulnerable_plugins();

		foreach ( $vulnerabilities as $plugin_name => $plugin_vulnerabilities ) {
			foreach ( $plugin_vulnerabilities as $vuln ) {
				$mail_body .= __( 'Vulnerability found', 'plugin-security-scanner' ) . ': ' . $vuln->title . "\n";
				$vulnerability_count++;
			}
		}

		// if vulns, email admin
		if ( $vulnerability_count ) {
			$mail_body .= "\n\n" . sprintf(_n(
				'Scan completed: %s vulnerability found.',
				'Scan completed: %s vulnerabilities found.',
			$vulnerability_count, 'plugin-security-scanner'), $vulnerability_count) . "\n";

			// Edited by JuhaniGeniem -->
			#wp_mail( $admin_email, get_bloginfo() . ' ' . __( 'Plugin Security Scan', 'plugin-security-scanner' ) . ' ' . date_i18n( get_option( 'date_format' ) ), $mail_body );
			
			if (function_exists('curl_version') && defined('PLUGIN_SECURITY_SCANNER_SLACK_KEY')) {
				$slack_message_expl = explode("\n\n", $mail_body);
				$slack_message = get_site_url()."\n".$slack_message_expl[0];
				$curl_message = array('payload' => json_encode(array('text' => $slack_message)));
				$c = curl_init(PLUGIN_SECURITY_SCANNER_SLACK_KEY);
				curl_setopt($c, CURLOPT_SSL_VERIFYPEER, false);
				curl_setopt($c, CURLOPT_POST, true);
				curl_setopt($c, CURLOPT_POSTFIELDS, $curl_message);
				curl_exec($c);
				curl_close($c);
			}
			else {
				$debug_to = 'support@geniem.com';
				$debug_subject = 'Automaattinen tietoturvatarkistus ei toimi - cURL puuttuu.';
				$debug_body = get_site_url()."<br><br>Palvelimelta ei löydy cURLia, joten automaattinen tietoturvatarkistus epäonnistuu.<br><br>Tämä sähköposti on lähetetty plugin-security-scanner.php:sta.";
				$debug_headers = array('Content-Type: text/html; charset=UTF-8');
				 
				wp_mail($debug_to, $debug_subject, $debug_body, $debug_headers);
			}
			// <-- Edited by JuhaniGeniem
		}
	}
}

register_deactivation_hook( __FILE__, 'prefix_deactivation' );

function prefix_deactivation() {
	wp_clear_scheduled_hook( 'plugin_security_scanner_daily_event_hook' );
}
