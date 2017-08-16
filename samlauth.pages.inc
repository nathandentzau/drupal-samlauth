<?php

/**
 * @file
 * Public facing page callbacks for the SamlAuth module.
 */

/**
 * Callback: samlauth_menu().
 * Route: saml/%samlauth/consume
 *
 * The Assertion Consumer Service to process the SAML Response from the
 * Identity Provider. Users are redirected from this page.
 *
 * @param string $idp_machine_name
 */
function samlauth_page_acs($idp_machine_name) {
  module_load_include('inc', 'samlauth', 'samlauth');

  // If the user is logged in already then redirect them away from this page.
  if (user_is_logged_in()) {
    $destination = samlauth_get_relay_state() ?: '<front>';

    drupal_goto($destination);
  }

  $auth = samlauth_instance($idp_machine_name);

  try {
    $request_id = samlauth_get_request_id();
    $auth->processResponse($request_id);

    if (!empty($auth->getErrors())) {
      throw new Exception($auth->getLastErrorReason());
    }

    // Attempt to login and/or register this user in Drupal.
    $account = samlauth_login_register(
      $auth->getNameId(),
      $idp_machine_name,
      $auth->getAttributes()
    );

    if (!$account) {
      throw new Exception('Error while attempting to login/register samlauth user.');
    }
  }
  catch (Exception $e) {
    watchdog('samlauth', $e->getMessage(), [], WATCHDOG_ERROR);
    drupal_set_message(t('There was an error processing your request.'), 'error');

    $redirect_locations = module_invoke_all('samlauth_error_redirect_url');

    if (!empty($redirect_locations)) {
      // Only get the first redirect location that is found. All others will
      // be ignored.
      $redirect_location = reset($redirect_locations);

      drupal_goto($redirect_location);
    }
  }

  $destination = samlauth_get_relay_state() ?: '<front>';

  drupal_goto($destination);
}

/**
 * Callback: samlauth_menu().
 * Route: saml/%samlauth/login
 *
 * This page initiates an AuthnRequest to the Identity Provider. All users are
 * redirected from this page.
 *
 * @param string $idp_machine_name
 */
function samlauth_page_login($idp_machine_name) {
  module_load_include('inc', 'samlauth', 'samlauth');

  $auth = samlauth_instance($idp_machine_name);
  $redirect = $auth->login(null, [], false, false, true);

  // Set the AuthnRequest ID in the current users session to be validated on
  // the SAML response.
  samlauth_set_request_id($auth->getLastRequestID());

  drupal_goto($redirect);
}

/**
 * Callback: samlauth_menu().
 * Route: saml/%samlauth/metadata.xml
 *
 * This page outputs the Service Provider metadata in XML.
 *
 * @param string $idp_machine_name
 */
function samlauth_page_metadata($idp_machine_name) {
  module_load_include('inc', 'samlauth', 'samlauth');

  drupal_add_http_header('Content-type', 'application/xml');

  // Print the XML to the browser.
  print samlauth_instance($idp_machine_name)
    ->getSettings()
    ->getSPMetadata();

  drupal_exit();
}
