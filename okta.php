<?php

/*
Plugin Name: Okta Authentication
Plugin URI: https://developer.wordpress.org/plugins/okta-authentication/
Description: Enables Okta integration for WordPress
Version: 0.0.1
Author: Zillow Group
Author URI: https://www.zillowgroup.com/
License: GPL2
License URI: https://www.gnu.org/licenses/gpl-2.0.html
Text Domain: okta
Domain Path: /languages
Documentation: https://developer.okta.com/quickstart/#/okta-sign-in-page/php/generic
*/

defined ( 'ABSPATH' ) or die( 'No dice.' );

if( ! class_exists( 'Okta' ) ) {

  class Okta {

    public function __construct () {

      /*
      Okta Variables
      */
      if ( ! function_exists( 'is_plugin_active_for_network' ) ) {
        require_once( ABSPATH . '/wp-admin/includes/plugin.php' );
      }
      $this->org_url = defined( 'OKTA_ORG_URL' ) ? OKTA_ORG_URL : ( is_plugin_active_for_network( 'okta/okta.php' ) ? get_site_option( 'okta_org_url' ) : get_option( 'okta_org_url' ) );
      $this->client_id = defined( 'OKTA_CLIENT_ID' ) ? OKTA_CLIENT_ID : ( is_plugin_active_for_network( 'okta/okta.php' ) ? get_site_option( 'okta_client_id' ) : get_option( 'okta_client_id' ) );
      $this->client_secret = defined( 'OKTA_CLIENT_SECRET' ) ? OKTA_CLIENT_SECRET : ( is_plugin_active_for_network( 'okta/okta.php' ) ? get_site_option( 'okta_client_secret' ) : get_option( 'okta_client_secret' ) );
      $this->auth_secret = base64_encode( $this->client_id . ':' . $this->client_secret );
      $this->base_url = $this->org_url . '/oauth2/default/v1';

      /*
      Redirect URI for Okta authentication loop
      */

      add_action( 'rest_api_init', array ( $this, 'RestApiInit' ) );

      /*
      Add Okta button to login page
      */

      add_action( 'login_message', array( $this, 'LoginMessage' ) );

      /*
      Register settings
      */

      add_action( 'admin_init', array( $this, 'AdminInit' ) );

      /*
      Admin menu
      */

      add_action( 'admin_menu', array( $this, 'AdminMenu' ) );
      add_action( 'network_admin_menu', array( $this, 'NetworkAdminMenu' ) );
      add_action( 'network_admin_edit_okta', array ( $this, 'SettingsSave' ) );

      /*
      Deactivation
      */

      register_deactivation_hook( __FILE__, array( $this, 'Deactivate' ) );

    }

    /*
    Register the rest API endpoint
    */

    function RestApiInit () {

      register_rest_route ( 'okta', '/auth', array(
        'methods' => 'GET',
        'callback' => array( $this, 'Auth' ),
      ) );

    }

    /*
    Authorize the user in Okta
    */

    function Auth ( WP_REST_Request $request ) {

      /*
      Validate the code and state
      */

      if ( array_key_exists ( 'state', $request ) && $request['state'] !== $state ) {

        die ( 'State does not match.' );

      }

      /*
      Convert the code to a token
      */

      $token = $this->Token ( $_GET['code'] );
      if ( is_wp_error( $token ) ) {

        die( 'TOKEN ERROR' );

      } else {

        /*
        Validate the token and return user data
        */

        $token = json_decode( $token['body'] );

        /*
        Get user detail
        */

        $user = $this->User ( $token->access_token );
        if ( is_wp_error ( $user ) ) {
          die( 'USER ERROR' );
        } else {

          /*
          Login the user
          */

          $user = json_decode ( $user['body'] );
          $this->Login ( $user );

        }

      }

    }

    /*
    Convert the code to a token
    */

    function Token ( $code ) {

      $url = $this->base_url . '/token?' . http_build_query (
        [
          'grant_type' => 'authorization_code',
          'code' => $code,
          'redirect_uri' => get_rest_url( null, 'okta/auth' )
        ]
      );

      $response = wp_safe_remote_post( $url, array(
        'headers' => array(
          'Accept' => 'application/json',
          'Authorization' => 'Basic ' . $this->auth_secret,
          'Content-Length' => 0,
          'Content-Type' => 'application/x-www-form-urlencoded'
        ),
        'sslverify' => false
      ) );

      return $response;

    }

    /*
    Get user detail
    */

    function User ( $token ){

      $url = $this->base_url . '/userinfo';
      $response = wp_safe_remote_post ( $url, array(
        'headers' => array (
          'Accept' => 'application/json',
          'Authorization' => 'Bearer ' . $token,
          'Content-Length' => 0,
          'Content-Type' => 'application/x-www-form-urlencoded'
        ),
        'sslverify' => false
      ) );

      return $response;

    }

    /*
    Login the user
    */

    function Login ( $user ){

      /*
      Get the username
      */

      $username = $user->preferred_username;

      /*
      Modify the username if necessary
      */

      if ( has_filter ( 'okta_username' ) ) {
        $username = apply_filters ( 'okta_username', $user );
      }

      /*
      Check to see if the user already exists
      */

      if ( false === ( $user_id = username_exists( $user->preferred_username ) ) ){

        /*
        Create the user
        */

        $user_id = wp_insert_user ( array(
          'user_login' => $username,
          'user_pass'  => wp_generate_password()
        ) );
        if ( is_wp_error ( $user_id ) ) {
          die( $user_id->get_error_message() );
        }

      }

      /*
      Get the user
      */

      $user = get_user_by ( 'id', $user_id );
      if ( is_wp_error ( $user_id ) ) {
        die( $user_id->get_error_message() );
      }

      /*
      Login the user
      */

      wp_set_current_user ( $user->ID, $user->user_login );
      wp_set_auth_cookie ( $user->ID );
      do_action ( 'wp_login', $user->user_login, $user );

      /*
      Redirect the user
      */

      if ( ! is_network_admin () ) {
        wp_redirect ( admin_url () );
      } else {
        wp_redirect ( network_admin_url () );
      }

      exit();

    }

    /*
    Add the Okta button to wp-login.php
    */

    function LoginMessage () {

      $url = apply_filters ( 'okta_login', $this->base_url . '/authorize?' . $query = http_build_query (
        [
          'client_id' => $this->client_id,
          'response_type' => 'code',
          'response_mode' => 'query',
          'scope' => 'openid profile',
          'redirect_uri' => get_rest_url( is_multisite() ? get_current_site()->blog_id : null, 'okta/auth' ),
          'state' => 'wordpress',
          'nonce' => wp_create_nonce( 'okta' )
        ]
      ) );

      ?>
      <style>
      .okta-logo{
        background-image: url(data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxMjUuMyA0MS44Ij4gIDxwYXRoIGQ9Ik0xNS43IDEwLjZDNyAxMC42IDAgMTcuNiAwIDI2LjNTNyA0MiAxNS43IDQyczE1LjctNyAxNS43LTE1LjctNy0xNS43LTE1LjctMTUuN3ptMCAyMy41Yy00LjMgMC03LjktMy40LTcuOS03LjggMC00LjMgMy40LTcuOSA3LjgtNy45aC4yYzQuMyAwIDcuOCAzLjYgNy44IDcuOS0uMiA0LjMtMy42IDcuOC03LjkgNy44em0yNy42LTIuNmMwLTEuMiAxLjUtMS45IDIuNC0xIDMuOSA0IDEwLjQgMTAuOSAxMC41IDEwLjkuMS4xLjIuMi42LjQuMiAwIC40LjEuNy4xaDcuMWMxLjMgMCAxLjctMS41IDEuMS0yLjJMNTQgMjcuN2wtLjgtLjdjLTEuMy0xLjYtMS4yLTIuMi4zLTMuOGw5LjMtMTAuNGMuNi0uNy4yLTIuMi0xLjEtMi4yaC03Yy0uNC4xLS41LjMtLjYuNCAwIDAtNS4yIDUuNi04LjQgOS0uOS45LTIuNC4zLTIuNC0xVjEuMkM0My4zLjMgNDIuNiAwIDQyIDBoLTUuM2MtLjkgMC0xLjQuNi0xLjQgMS4xdjM5LjZjMCAuOS44IDEuMiAxLjQgMS4ySDQyYy44IDAgMS4zLS42IDEuMy0xLjJ2LTkuMnptNDIuOSA5bC0uNi01LjNjLS4xLS43LS43LTEuMi0xLjQtMS4xaC0uMWMtLjQuMS0uOC4xLTEuMi4xLTQuMiAwLTcuNi0zLjMtNy44LTcuNFYyMGMwLS44LjYtMS41IDEuNS0xLjVoN2MuNSAwIDEuMi0uNCAxLjItMS40di01YzAtMS0uNi0xLjUtMS4yLTEuNWgtNy4xYy0uOCAwLTEuNS0uNi0xLjUtMS40di04YzAtLjUtLjQtMS4yLTEuNC0xLjJoLTUuMmMtLjcgMC0xLjMuNC0xLjMgMS4ydjI1LjZjLjIgOC41IDcuMiAxNS4zIDE1LjcgMTUuMy43IDAgMS40LS4xIDIuMS0uMS45LS4yIDEuNC0uOCAxLjMtMS41ek0xMjQgMzMuOWMtNC41IDAtNS4xLTEuNi01LjEtNy42VjExLjljMC0uNS0uNC0xLjMtMS40LTEuM2gtNS4yYy0uNyAwLTEuNC41LTEuNCAxLjN2LjdjLTIuNC0xLjMtNS0yLjEtNy43LTIuMS04LjcgMC0xNS43IDctMTUuNyAxNS43czcgMTUuNyAxNS43IDE1LjdjMy45IDAgNy41LTEuNCAxMC4yLTMuOCAxLjUgMi4yIDMuOSAzLjcgNy42IDMuOC42IDAgNCAuMSA0LTEuNXYtNS42YzAtLjQtLjQtLjktMS0uOXptLTIwLjguMmMtNC4zIDAtNy45LTMuNC03LjktNy44czMuNC03LjkgNy44LTcuOWguMmM0LjMgMCA3LjggMy42IDcuOCA3LjktLjIgNC4zLTMuNiA3LjgtNy45IDcuOHoiLz48L3N2Zz4=);
        background-position: center;
        background-repeat: no-repeat;
        height: 30px;
        margin-bottom: 20px;
        overflow: hidden;
        text-indent: 100%;
      }
      </style>
      <form style="padding-bottom: 26px; text-align: center;">
        <div class="okta-logo">
          Okta
        </div>
        <a href="<?php echo $url; ?>" class="button">
          Log In with Okta
        </a>
      </form>
      <p style="margin-top: 20px; text-align: center;">
        or
      </p>
      <?php

    }

    /*
    Register settings
    */

    function AdminInit () {

      register_setting ( 'okta', 'okta_org_url' );
      register_setting ( 'okta', 'okta_client_id' );
      register_setting ( 'okta', 'okta_client_secret' );

    }

    /*
    Create the settings page
    */

    function AdminMenu () {

      add_menu_page ( 'Okta Authentication', 'Okta', 'manage_options', 'okta', array( $this, 'SettingsPage' ), 'dashicons-lock' );

    }

    /*
    Create the settings page
    */

    function NetworkAdminMenu () {

      add_menu_page ( 'Okta Authentication', 'Okta', 'manage_network_options', 'okta', array( $this, 'SettingsPage' ), 'dashicons-lock' );

    }

    /*
    Render the settings page
    */

    function SettingsPage () {

      ?>
      <div class="wrap">
        <h1>
          Okta Authentication
        </h1>
        <form action="<?php echo is_network_admin() ? network_admin_url( 'edit.php?action=okta' ) : admin_url( 'options.php' ) ; ?>" method="post" autocomplete="off">
          <?php settings_fields ( 'okta' ); ?>
          <?php do_settings_sections ( 'okta' ); ?>
          <h2 class="title">
            Step 1
          </h2>
          <p>
            <a href="https://login.okta.com/" target="_blank">Log in</a> to or <a href="https://developer.okta.com/signup/" target="_blank">sign up</a> for an Okta account. It's free to create a developer account.
          </p>
          <h2 class="title">
            Step 2
          </h2>
          <p>
            Go to the Dashboard of your Developer Console. At the top right of the screen, you should see your Org URL (ex: https://dev-123.oktapreview.com). Copy and paste that URL into the field below.
          </p>
          <table class="form-table">
            <tr valign="top">
              <th scope="row">
                <?php _e( 'Org URL', 'okta' ); ?>
              </th>
              <td>
                <input type="url" name="okta_org_url" value="<?php echo $this->org_url; ?>" size="40"<?php if ( defined( 'OKTA_ORG_URL' ) ) echo ' disabled readonly' ?>>
              </td>
            </tr>
          </table>
          <h2 class="title">
            Step 3
          </h2>
          <p>
            Go to the Applications section of your Developer Console. Create a new Web application and enter these URLs when prompted.
          </p>
          <table class="form-table">
            <tr valign="top">
              <th scope="row">
                <?php _e( 'Base URI', 'okta' ); ?>
              </th>
              <td>
                <a href="<?php echo get_site_url(); ?>" target="_blank">
                  <?php echo get_site_url(); ?>
                </a>
              </td>
            </tr>
              <tr valign="top">
                <th scope="row">
                  <?php _e( 'Login Redirect URI', 'okta' ); ?>
                </th>
                <td>
                  <a href="<?php echo get_rest_url( null, 'okta/auth' ); ?>" target="_blank">
                    <?php echo get_rest_url( null, 'okta/auth' ); ?>
                  </a>
                </td>
              </tr>
          </table>
          <h2 class="title">
            Step 4
          </h2>
          <p>
            Once you've created the application, go to the General tab and scroll down to the Client Credentials section. Copy and paste those values in the fields below.
          </p>
          <table class="form-table">
            <tr valign="top">
              <th scope="row">
                <?php _e( 'Client ID', 'okta' ); ?>
              </th>
              <td>
                <input type="text" name="okta_client_id" value="<?php echo $this->client_id; ?>" size="40"<?php if ( defined( 'OKTA_CLIENT_ID' ) ) echo ' disabled readonly' ?>>
              </td>
            </tr>
            <tr valign="top">
              <th scope="row">
                <?php _e( 'Client Secret', 'okta' ); ?>
              </th>
              <td>
                <input type="password" name="okta_client_secret" value="<?php echo $this->client_secret; ?>" size="40"<?php if ( defined( 'OKTA_CLIENT_SECRET' ) ) echo ' disabled readonly' ?>>
              </td>
            </tr>
          </table>
          <?php submit_button (); ?>
        </form>
      </div>
      <?php

    }

    /*
    Update settings for multisite network
    */

    function SettingsSave () {

      /*
      Validate the request via nonce, referrer and capabilities
      */

      if ( ! wp_verify_nonce( $_POST['_wpnonce'], 'okta' ) || ! current_user_can( 'manage_network_options' ) ) {
        wp_die( 'No dice.' );
      }else{
        check_admin_referer( 'okta' );
      }

      /*
      Update network settings
      */

      if ( isset( $_POST['okta_org_url'] ) && filter_var( $_POST['okta_org_url'], FILTER_VALIDATE_URL ) ) {
        update_site_option( 'okta_org_url', esc_url_raw( $_POST['okta_org_url'], array( 'https' ) ) );
      }
      if ( isset( $_POST['okta_client_id'] ) ) {
        update_site_option( 'okta_client_id', sanitize_key( $_POST['okta_client_id'] ) );
      }
      if ( isset( $_POST['okta_client_secret'] ) ) {
        update_site_option( 'okta_client_secret', sanitize_key( $_POST['okta_client_secret'] ) );
      }

      /*
      Redirect the user
      */

      wp_redirect ( $_POST['_wp_http_referer'] );
      exit();

    }

    function Deactivate () {

      if ( is_network_admin () ) {

        /*
        Delete network settings
        */

        delete_site_option ( 'okta_org_url' );
        delete_site_option ( 'okta_client_id' );
        delete_site_option ( 'okta_client_secret' );

      } else {

        /*
        Delete blog settings
        */

        delete_option ( 'okta_org_url' );
        delete_option ( 'okta_client_id' );
        delete_option ( 'okta_client_secret' );


      }
    }

  }

  new Okta;

}
