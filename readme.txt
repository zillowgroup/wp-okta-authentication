=== Okta Authentication ===
Contributors: zillowgroup, heyjones
Donate link: https://www.zillowgroup.com
Tags: okta, authentication
Requires at least: 3.0.1
Tested up to: 4.9.6
Requires PHP: 5.2.4
Stable tag: trunk
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

== Description ==

Enables Okta integration for WordPress. This plugin requires that you have an Okta account. You can create a development account for free at https://developer.okta.com/signup/.

== Installation ==

Simply install and activate the plugin. There will be an Okta item in your admin menu with full instructions on how to configure your Okta integration. The client key and secret that you provide will be stored in the database, unless you add them to your wp-config.php. Those values get sent over to the Okta server URL that you provide in order to interact with your Okta app and authenticate the user. The response is not cached in WordPress, and the Okta tokens automatically expire.

== Frequently Asked Questions ==

== Screenshots ==

== Changelog ==

= 0.0.3 =

* Fix for user creation with invalid password
* Adjust login flow for custom user mapping
* Escaping and L10N

= 0.0.2 =

* Fix for okta_username filter

= 0.0.1 =

* Initial commit

== Upgrade Notice ==
