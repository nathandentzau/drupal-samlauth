<?php

/**
 * @file
 * Helper functions for the SamlAuth module.
 */

/**
 * Clean the specified string by removing all special characters.
 *
 * @param string $string
 *
 * @return string
 */
function samlauth_clean_string($string) {
  $string = preg_replace('/[^\w]+/', '_', $string);
  $string = strtolower($string);

  return $string;
}

/**
 * Get the Service Provider Entity ID based on the Identity Provider.
 *
 * @param string $idp_machine_name
 *
 * @return string
 *   A formatted URL representing the SP Entity ID.
 */
function samlauth_entity_id($idp_machine_name) {
  return url('saml/' . $idp_machine_name, ['absolute' => TRUE]);
}

/**
 * Get the RelayState from the query string.
 *
 * @return string|NULL
 *   The RelayState path if the destination passed validation, or NULL if the
 *   RelayState is not given or if the destination path is malformed.
 */
function samlauth_get_relay_state() {
  $relay_state = samlauth_get_relay_state_parameter();

  // parse_url() may return FALSE for a malformed URL, if so return NULL before
  // we start building our result.
  if (empty($relay_state['path'])) {
    return NULL;
  }

  $result = $relay_state['path'];

  if (isset($relay_state['query'])) {
    $result .= '?' . $relay_state['query'];
  }

  if (isset($relay_state['fragment'])) {
    $result .= '#' . $relay_state['fragment'];
  }

  return $result;
}

/**
 * Get the RelayState parameter from either GET or POST method.
 *
 * @return array|null
 */
function samlauth_get_relay_state_parameter() {
  if (isset($_GET['RelayState'])) {
    return parse_url($_GET['RelayState']);
  }

  if (isset($_POST['RelayState'])) {
    return parse_url($_POST['RelayState']);
  }

  return NULL;
}

/**
 * A procedural multiton holding the OneLogin_Saml2_Auth instance.
 *
 * @param string $idp_machine_name
 *
 * @return OneLogin_Saml2_Auth
 */
function samlauth_instance($idp_machine_name) {
  $instance = &drupal_static(__FUNCTION__ . $idp_machine_name);

  if ($instance) {
    return $instance;
  }

  $settings = samlauth_settings($idp_machine_name);
  $settings = samlauth_settings_onelogin_format($settings);

  $instance = new OneLogin\Saml2\Auth($settings);

  return $instance;
}

/**
 * Check whether the current user is authenticated through samlauth.
 *
 * @return bool
 */
function samlauth_is_authenticated() {
  return isset($_SESSION['samlauth_authenticated']) && $_SESSION['samlauth_authenticated'];
}

/**
 * Set the current user's session as authenticated through samlauth.
 */
function samlauth_set_authenticated() {
  $_SESSION['samlauth_authenticated'] = TRUE;
}

/**
 * Load the private key from the filesystem.
 *
 * @param string $path
 *   A relative or absolute path to the private key. Relative paths are
 *   prepended with the DRUPAL_ROOT constant.
 *
 * @return string|false
 *   Returns the contents of the private key file or false if the file does not
 *   exist on the filesystem.
 */
function samlauth_load_private_key($path) {
  // If the path is not absolute then prepend the DRUPAL_ROOT to the path.
  if (strpos($path, '/') !== 0) {
    $path = DRUPAL_ROOT . '/' . $path;
  }

  if (!file_exists($path)) {
    return FALSE;
  }

  return file_get_contents($path);
}

/**
 * Login and/or Register a SamlAuth user.
 *
 * @param string $name_id
 *   The subjectNameId specified in the SAML assertion.
 * @param string $idp_machine_name
 *   The machine name of the IdP.
 * @param array $saml_attributes
 *   An array of SAML attributes specified in the SAML assertion.
 *
 * @return stdClass|false
 *   If the user account was created a Drupal user object is returned, if there
 *   was an error then false is returned.
 */
function samlauth_login_register($name_id, $idp_machine_name, array $saml_attributes) {
  $settings = samlauth_settings($idp_machine_name);

  // If SAML users are to be mapped to Drupal user then attempt to load their
  // account by the email address specified in the SAML assertion. If we're not
  // mapping SAML users to local accounts then attempt to load their account
  // by the subjectNameId stored in the authmaps table.
  if ($settings['map_users']) {
    $email = !empty($saml_attributes[$settings['map_users_email']])
      ? $saml_attributes[$settings['map_users_email']][0]
      : NULL;

    $account = user_load_by_mail($email);
  }
  else {
    $account = user_external_load($name_id);
  }

  // If the SAML user's account could not be located and provisioning users in
  // Drupal is enabled, then attempt to create an account for the user.
  if (!$account && $settings['create_users']) {
    $name = !empty($saml_attributes[$settings['user_name_attribute']])
      ? $saml_attributes[$settings['user_name_attribute']][0]
      : NULL;

    if (!$name) {
      watchdog(
        'samlauth',
        'Cannot create an account. Username attribute was not found.',
        [],
        WATCHDOG_ERROR
      );

      return FALSE;
    }

    // Sanitize the subjectNameId to prevent special characters from enterting
    // the Drupal username.
    $name = samlauth_clean_string($name);

    $email = !empty($saml_attributes[$settings['user_mail_attribute']])
      ? $saml_attributes[$settings['user_mail_attribute']][0]
      : NULL;

    if (!$email) {
      watchdog(
        'samlauth',
        'Cannot create an account. Email attribute was not found.',
        [],
        WATCHDOG_ERROR
      );

      return FALSE;
    }

    // Register this new user.
    $userinfo = [
      'name' => $name,
      'pass' => user_password(32), // Generate a strong random password.
      'mail' => $email,
      'init' => $email,
      'status' => 1,
      'access' => REQUEST_TIME,
    ];

    // Define unalterable context for the alter hook.
    $context = [
      'attributes' => $saml_attributes,
      'idp' => $idp_machine_name,
    ];

    // Allow other modules to modify the userinfo when creating an account.
    drupal_alter('samlauth_userinfo', $userinfo, $context);

    // Create a new user account.
    $account = user_save(drupal_anonymous_user(), $userinfo);

    if (!$account) {
      watchdog(
        'samlauth',
        'There was an error when creating the account.',
        [],
        WATCHDOG_ERROR
      );

      return FALSE;
    }

    // Set the account as new!
    $account->is_new = TRUE;

    // Save this user's new account reference in the authmap table.
    user_set_authmaps($account, [
      'authname_samlauth_' . $idp_machine_name => $name_id,
    ]);
  }

  if (!$account) {
    watchdog(
      'samlauth',
      implode(' ', [
        'No existing user account matches the SAML ID provided.',
        'This authentication service is not configured to create new accounts.',
      ]),
      [],
      WATCHDOG_ERROR
    );

    return FALSE;
  }

  // Set the user's session as authenticated through samlauth.
  samlauth_set_authenticated();

  // Log user in.
  $form_state['uid'] = $account->uid;
  $form_state['samlauth'] = TRUE;

  user_login_submit([], $form_state);

  watchdog('samlauth', 'User %name logged in from IdP %idp.', [
    '%name' => $account->name,
    '%idp' => $idp_machine_name
  ]);

  // Allow other modules to take action when a SAML user logs in.
  module_invoke_all(
    'samlauth_login',
    $account,
    $idp_machine_name,
    $saml_attributes
  );

  return $account;
}

/**
 * Get the settings for a saved Identity Provider.
 *
 * @param string $idp_machine_name
 *
 * @return array
 */
function samlauth_settings($idp_machine_name) {
  // Gather settings set in settings.php
  $settings = !empty($GLOBALS['conf']['samlauth'])
    ? $GLOBALS['conf']['samlauth']
    : NULL;

  // If there are global settings and the IdP machine name is in the global
  // settings then merge the settings with the default settings array.
  if ($settings && array_key_exists($idp_machine_name, $settings)) {
    return samlauth_settings_merge($settings[$idp_machine_name]);
  }

  $result = db_select('samlauth_settings')
    ->fields('samlauth_settings')
    ->condition('idp_machine_name', $idp_machine_name)
    ->execute();

  if ($row = $result->fetchAssoc()) {
    return $row;
  }

  return [];
}

/**
 * Format the Identity Provider settings to be injected into the
 * OneLogin_Saml2_Auth class.
 *
 * @param array $settings
 *   SamlAuth Identity Provider settings.
 *
 * @return array
 */
function samlauth_settings_onelogin_format(array $settings) {
  $settings = [
    'strict' => TRUE,
    'sp' => [
      'entityId' => samlauth_entity_id($settings['idp_machine_name']),
      'assertionConsumerService' => [
        'url' => samlauth_url_acs($settings['idp_machine_name']),
      ],
      'NameIDFormat' => $settings['sp_name_id_format'],
      'x509cert' => $settings['sp_x509_certificate'],
      'privateKey' => samlauth_load_private_key($settings['sp_private_key']),
    ],
    'idp' => [
      'entityId' => $settings['idp_entity_id'],
      'singleSignOnService' => [
        'url' => $settings['idp_single_sign_on_service'],
      ],
      'x509cert' => $settings['idp_x509_certificate'],
    ],
    'security' => [
      'authnRequestSigned' => (bool) $settings['security_authn_requests_sign'],
      'wantMessagesSigned' => (bool) $settings['security_messages_sign'],
      'wantAssertionsEncrypted' => (bool) $settings['security_signed_assertion'],
      'wantAssertionsSigned' => (bool) $settings['security_encrypted_assertion'],
      'wantNameId' => TRUE,
      'wantNameIdSigned' => (bool) $settings['security_name_id_sign'],
      'signatureAlgorithm' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
      'digestAlgorithm' => 'http://www.w3.org/2001/04/xmlenc#sha256',
    ],
  ];

  drupal_alter('samlauth_settings', $settings);

  return $settings;
}

/**
 * Get a map of default settings values for Identity Providers.
 *
 * @return array
 */
function samlauth_settings_map() {
  return [
    'idp_machine_name' => 'default',
    'sp_name_id_format' => '',
    'sp_x509_certificate' => '',
    'sp_private_key' => '',
    'idp_entity_id' => '',
    'idp_single_sign_on_service' => '',
    'idp_x509_certificate' => '',
    'map_users' => 0,
    'map_users_email' => '',
    'create_users' => 0,
    'user_name_attribute' => '',
    'user_mail_attribute' => '',
    'security_authn_requests_sign' => 0,
    'security_messages_sign' => 0,
    'security_name_id_sign' => 0,
    'security_signed_assertion' => 0,
    'security_encrypted_assertion' => 0,
  ];
}

/**
 * Merge custom settings values with the default settings map. Any settings
 * keys that do not exist in the default settings map will be unset.
 *
 * @param array $settings
 *
 * @return array
 */
function samlauth_settings_merge(array $settings) {
  $settings_map = samlauth_settings_map();

  // Filter out settings keys that are not defined in the default settings map.
  $settings = array_filter($settings, function ($key) use ($settings_map) {
    return array_key_exists($key, $settings_map);
  }, ARRAY_FILTER_USE_KEY);

  return array_merge($settings_map, $settings);
}

/**
 * Save settings for an Identity Provider.
 *
 * @param string $idp_machine_name
 * @param array $settings
 *
 * @return int
 *   The status returned from the executing the merge query.
 */
function samlauth_settings_save($idp_machine_name, array $settings) {
  $settings = samlauth_settings_merge($settings);
  $settings['idp_machine_name'] = $idp_machine_name;

  return db_merge('samlauth_settings')
    ->key([
      'idp_machine_name' => $idp_machine_name,
    ])
    ->fields($settings)
    ->execute();
}

/**
 * A drupal mapped associative array for allowed subjectNameIds.
 *
 * @return array
 */
function samlauth_subject_name_id_map() {
  return drupal_map_assoc([
    OneLogin\Saml2\Constants::NAMEID_EMAIL_ADDRESS,
    OneLogin\Saml2\Constants::NAMEID_X509_SUBJECT_NAME,
    OneLogin\Saml2\Constants::NAMEID_WINDOWS_DOMAIN_QUALIFIED_NAME,
    OneLogin\Saml2\Constants::NAMEID_UNSPECIFIED,
    OneLogin\Saml2\Constants::NAMEID_KERBEROS,
    OneLogin\Saml2\Constants::NAMEID_ENTITY,
    OneLogin\Saml2\Constants::NAMEID_TRANSIENT,
    OneLogin\Saml2\Constants::NAMEID_PERSISTENT,
    OneLogin\Saml2\Constants::NAMEID_ENCRYPTED,
  ]);
}

/**
 * A formatted URL to the Identity Provider's Assertion Comsumer Service.
 *
 * @param string $idp_machine_name
 *
 * @return string
 */
function samlauth_url_acs($idp_machine_name) {
  return url('saml/' . $idp_machine_name . '/consume', [
    'absolute' => TRUE,
  ]);
}

/**
 * A formatted URL to the Identity Provider's metadata file.
 *
 * @param string $idp_machine_name
 *
 * @return string
 */
function samlauth_url_metadata($idp_machine_name) {
  return url('saml/' . $idp_machine_name . '/metadata.xml', [
    'absolute' => TRUE,
  ]);
}

/**
 * Get the user's AuthnRequest ID from the session.
 *
 * @return string|null
 */
function samlauth_get_request_id() {
  return !empty($_SESSION[SAMLAUTH_REQUEST_ID])
    ? $_SESSION[SAMLAUTH_REQUEST_ID]
    : null;
}

/**
 * Set the user's AuthnRequest ID to the session.
 *
 * @param string $request_id
 *   An AuthnRequest ID.
 */
function samlauth_set_request_id($request_id) {
  $_SESSION[SAMLAUTH_REQUEST_ID] = $request_id;
}
