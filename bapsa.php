<?php
/**
* Plugin Name: Basic Auth Protect Site Access
* Description: Puts a HTTP auth on staging. Just to keep search engines out, passwords in clear text!
* Author: uptimizt
* Author URI: https://github.com/uptimizt
* Text Domain: bapsa
* Version: 1.1
*/
class BasicAuthProtectSiteAccess
{
  /**
   * Holds the values to be used in the fields callbacks
   */
  private static $options;

  /**
   * Hold the values for multisite setup
   */
  private static $options_ms;

  /**
   * Start up
   */
  public static function init()
  {
    add_action( 'init', array( __CLASS__, 'password_protect') );

    add_action( 'admin_init', array( __CLASS__, 'settings_init' ) );
    add_action( 'admin_menu', array( __CLASS__, 'add_settings' ) );

    add_action( 'network_admin_menu', array( __CLASS__, 'add_network_settings' ) );

    add_action( 'network_admin_edit_save_password_protect_staging_option', array( __CLASS__, 'save_option_for_network') );
  }

  /**
   * Main function for restrict site access by Basic Auth
   */
  function password_protect() {
    $options = get_site_option( 'password_protect_staging_option' );
    if(empty($options)){
      $options = get_option( 'password_protect_staging_option' );
    }

    $options = apply_filters('bapsa_options', $options);

    // no user or pw = not protected
    if (empty($options['username']) || empty($options['password'])) {
      return;
    }

    if (!is_admin() && (!isset($_SERVER['PHP_AUTH_USER']) || ($_SERVER['PHP_AUTH_USER'] != $options['username'] ) || ($_SERVER['PHP_AUTH_PW'] != $options['password'] ))) {
        header('WWW-Authenticate: Basic realm="Staging"');
        header('HTTP/1.0 401 Unauthorized');
        echo 'Access denied';
        exit;
    }
  }

  /**
   * Save options for network
   */
  function save_option_for_network()
  {
    $url_redirect = add_query_arg(
      array( 'page' => 'password-protect-staging' ),
      network_admin_url( 'settings.php' )
    );

    if( ! empty($_POST['password_protect_staging_option']) ){
      $option_value = $_POST['password_protect_staging_option'];

      if(is_array($option_value)){
        if(update_site_option( 'password_protect_staging_option', $option_value )){
          $url_redirect = add_query_arg(
            array( 'page' => 'password-protect-staging', 'updated' => 'true' ),
            network_admin_url( 'settings.php' )
          );
        }
      }
    }
    // redirect to settings page in network
    wp_redirect($url_redirect);
    exit;
  }

  /**
   * Add options page for network
   */
  public static function add_network_settings()
  {
    add_submenu_page(
      'settings.php',
      $page_title = 'Basic Auth Protect',
      $menu_title = 'Basic Auth Protect',
      $capability = 'manage_network_options',
      $menu_slug = 'password-protect-staging',
      $function = array( __CLASS__, 'display_admin_page_for_multisite' )
    );
  }

  /**
   * Add options page
   */
  public static function add_settings()
  {
    // This page will be under "Settings"
    add_options_page(
        'Basic Auth Protect',
        'Basic Auth Protect',
        'manage_options',
        'password-protect-staging',
        array( __CLASS__, 'display_admin_page' )
    );
  }

  /**
   * Display admin page for Site Network
   */
  public static function display_admin_page_for_multisite(){

   if (isset($_GET['updated'])){
     printf(
       '<div id="message" class="updated notice is-dismissible"><p>%s</p></div>',
       __('Options saved.')
     );
   }

    self::$options_ms = get_site_option( 'password_protect_staging_option', '', true );

    $url_form = esc_url(
        add_query_arg(
           'action',
           'save_password_protect_staging_option',
           network_admin_url( 'edit.php' )
        )
    );

    ?>
    <div class="wrap">
        <h2>Basic Auth Protect Site Access</h2>
        <form method="post" action="<?= $url_form ?>">
        <?php
            // This prints out all hidden setting fields
            settings_fields( 'password_protect_staging_group' );
            do_settings_sections( 'password-protect-staging' );
            submit_button();
        ?>
        </form>
    </div>
    <?php
  }

  /**
   * Options page callback
   */
  public static function display_admin_page()
  {
      // Set class property
      self::$options = get_option( 'password_protect_staging_option' );
      ?>
      <div class="wrap">
          <h2>Basic Auth Protect Site Access</h2>
          <form method="post" action="options.php">
          <?php
              // This prints out all hidden setting fields
              settings_fields( 'password_protect_staging_group' );
              do_settings_sections( 'password-protect-staging' );
              submit_button();
          ?>
          </form>
      </div>
      <?php
  }

  /**
   * Register and add settings
   */
  public static function settings_init()
  {
      register_setting(
          'password_protect_staging_group', // Option group
          'password_protect_staging_option', // Option name
          array( __CLASS__, 'sanitize' ) // Sanitize
      );

      add_settings_section(
          'password_protect_staging_id', // ID
          'Username/Password', // Title
          array( __CLASS__, 'display_section' ), // Callback
          'password-protect-staging' // Page
      );

      add_settings_field(
          'username', // ID
          'Username', // Title
          array( __CLASS__, 'display_form_input_username' ), // Callback
          'password-protect-staging', // Page
          'password_protect_staging_id' // Section
      );

      add_settings_field(
          'password',
          'Password',
          array( __CLASS__, 'display_form_input_password' ),
          'password-protect-staging',
          'password_protect_staging_id'
      );
  }

  /**
   * Sanitize each setting field as needed
   *
   * @param array $input Contains all settings fields as array keys
   */
  public static function sanitize( $input )
  {
      $new_input = array();

      if( isset( $input['username'] ) )
          $new_input['username'] = sanitize_text_field( $input['username'] );

      if( isset( $input['password'] ) )
          $new_input['password'] = sanitize_text_field( $input['password'] );

      return $new_input;
  }

  /**
   * Print the Section text
   */
  public static function display_section()
  {
      print 'Enter your settings below:';
  }

  /**
   * Get the settings option array and print one of its values
   */
  public static function display_form_input_username()
  {
    if(is_multisite()){
      printf(
          '<input type="text" id="title" name="password_protect_staging_option[username]" value="%s" />',
          isset( self::$options_ms['username'] ) ? esc_attr( self::$options_ms['username']) : ''
      );

    } else {
      printf(
          '<input type="text" id="title" name="password_protect_staging_option[username]" value="%s" />',
          isset( self::$options['username'] ) ? esc_attr( self::$options['username']) : ''
      );

    }
  }

  /**
   * Get the settings option array and print one of its values
   */
  public static function display_form_input_password()
  {
    if(is_multisite()){
      printf(
          '<input type="text" id="password" name="password_protect_staging_option[password]" value="%s" />',
          isset( self::$options_ms['password'] ) ? esc_attr( self::$options_ms['password']) : ''
      );

    } else{
      printf(
          '<input type="text" id="password" name="password_protect_staging_option[password]" value="%s" />',
          isset( self::$options['password'] ) ? esc_attr( self::$options['password']) : ''
      );

    }
  }
}

BasicAuthProtectSiteAccess::init();
