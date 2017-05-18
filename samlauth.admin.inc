<?php

/**
 * @file
 * Callback functions for the admin pages for the SamlAuth module.
 */

/**
 * Callback: drupal_get_form().
 *
 * The admin settings form for this module.
 */
function samlauth_admin_settings(array $form, array &$form_state) {
  module_load_include('inc', 'samlauth', 'samlauth');

  $settings = samlauth_settings('default');
  $settings = samlauth_settings_merge($settings);

  $form['service_provider'] = [
    '#type' => 'fieldset',
    '#title' => t('Service Provider Configuration'),
  ];

  $form['service_provider']['config_info'] = [
    '#theme' => 'item_list',
    '#items' => [
      t('Entity ID') . ': ' . samlauth_entity_id($settings['idp_machine_name']),
      t('Metadata URL') . ': ' . samlauth_url_metadata(
        $settings['idp_machine_name']
      ),
      t('Assertion Consumer Service') . ': ' . samlauth_url_acs(
        $settings['idp_machine_name']
      ),
    ],
    '#empty' => [],
    '#list_type' => 'ul',
  ];

  $form['service_provider']['sp_name_id_format'] = [
    '#type' => 'select',
    '#title' => t('Name ID Format'),
    '#description' => t(
      'Specify the NameIDFormat attribute to request from the identity provider'
    ),
    '#options' => samlauth_subject_name_id_map(),
    '#default_value' => $settings['sp_name_id_format'],
  ];

  $form['service_provider']['sp_x509_certificate'] = [
    '#type' => 'textarea',
    '#title' => t('x509 Certificate'),
    '#description' => t(implode(' ', [
      'Public x509 certificate of the SP. No line breaks',
      'or BEGIN CERTIFICATE or END CERTIFICATE lines.',
    ])),
    '#default_value' => $settings['sp_x509_certificate'],
  ];

  $form['service_provider']['sp_private_key'] = [
    '#type' => 'textfield',
    '#title' => t('Private Key'),
    '#description' => t(implode(' ', [
      'Private key path for SP. Relative paths on the',
      'filesystem are from the DRUPAL_ROOT.',
    ])),
    '#default_value' => $settings['sp_private_key'],
  ];

  $form['identity_provider'] = [
    '#type' => 'fieldset',
    '#title' => t('Identity Provider Configuration'),
  ];

  $form['identity_provider']['idp_entity_id'] = [
    '#type' => 'textfield',
    '#title' => t('Entity ID'),
    '#description' => t(
      'Specifies the identifier to be used to represent the IDP.'
    ),
    '#default_value' => $settings['idp_entity_id'],
  ];

  $form['identity_provider']['idp_single_sign_on_service'] = [
    '#type' => 'textfield',
    '#title' => t('Single Sign On Service'),
    '#description' => t(
      'URL where the SP will send the authentication request message.'
    ),
    '#default_value' => $settings['idp_single_sign_on_service'],
  ];

  $form['identity_provider']['idp_x509_certificate'] = [
    '#type' => 'textarea',
    '#title' => t('x509 Certificate'),
    '#description' => t('Public x509 certificate of the IdP'),
    '#default_value' => $settings['idp_x509_certificate'],
  ];

  $form['user_info'] = [
    '#title' => t('User Info and Syncing'),
    '#type' => 'fieldset',
  ];

  $form['user_info']['map_users'] = [
    '#type' => 'checkbox',
    '#title' => t('Attempt to map SAML users to existing local users?'),
    '#description' => t(implode(' ', [
      'If this option is enabled and a SAML authentication response is',
      "received for a user that already exists locally, and the user's email",
      'matches the configured attribute, the SAML user will be mapped to the',
      'local user and then logged in.',
    ])),
    '#default_value' => $settings['map_users'],
  ];

  $form['user_info']['map_users_email'] = [
    '#type' => 'textfield',
    '#title' => t('Email attribute (for mapping)'),
    '#description' => t(
      'This attribute will be used for mapping SAML users to local Drupal users.'
    ),
    '#default_value' => $settings['map_users_email'],
    '#states' => [
      'invisible' => [
        ':input[name="map_users"]' => ['checked' => FALSE],
      ],
    ],
  ];

  $form['user_info']['create_users'] = [
    '#type' => 'checkbox',
    '#title' => t('Create users specified by SAML server?'),
    '#description' => t(' ', [
      'If this option is enabled, users that do not exist in the Drupal',
      'database will be created if specified by a successful SAML',
      'authentication response.',
    ]),
    '#default_value' => $settings['create_users'],
  ];

  $form['user_info']['user_name_attribute'] = [
    '#type' => 'textfield',
    '#title' => t('User name attribute'),
    '#description' => t(implode(' ', [
      'When SAML users are created, this field specifies which SAML attribute',
      'should be used for the Drupal user name.<br />Example: <em>cn</em>',
      'or <em>eduPersonPrincipalName</em>',
    ])),
    '#default_value' => $settings['user_name_attribute'],
    '#states' => [
      'invisible' => [
        ':input[name="create_users"]' => ['checked' => FALSE],
      ],
    ],
  ];

  $form['user_info']['user_mail_attribute'] = [
    '#type' => 'textfield',
    '#title' => t('User email attribute'),
    '#description' => t(implode(' ', [
      'When SAML users are created, this field specifies which SAML',
      'attribute should be used for the Drupal email address.',
      '<br />Example: <em>mail</em>',
    ])),
    '#default_value' => $settings['user_mail_attribute'],
    '#states' => [
      'invisible' => [
        ':input[name="create_users"]' => ['checked' => FALSE],
      ],
    ],
  ];

  $form['security'] = [
    '#title' => t('Security Options'),
    '#type' => 'fieldset',
  ];

  $form['security']['security_authn_requests_sign'] = [
    '#type' => 'checkbox',
    '#title' => t('Request signed AuthnRequests'),
    '#default_value' => $settings['security_authn_requests_sign'],
  ];

  $form['security']['security_messages_sign'] = [
    '#type' => 'checkbox',
    '#title' => t('Request signed messages'),
    '#default_value' => $settings['security_messages_sign'],
  ];

  $form['security']['security_name_id_sign'] = [
    '#type' => 'checkbox',
    '#title' => t('Request signed NameID'),
    '#default_value' => $settings['security_name_id_sign'],
  ];

  $form['security']['security_signed_assertion'] = [
    '#type' => 'checkbox',
    '#title' => t('Request signed assertion'),
    '#default_value' => $settings['security_signed_assertion'],
  ];

  $form['security']['security_encrypted_assertion'] = [
    '#type' => 'checkbox',
    '#title' => t('Request encrypted assertion'),
    '#default_value' => $settings['security_encrypted_assertion'],
  ];

  $form['submit'] = [
    '#type' => 'submit',
    '#value' => t('Save'),
  ];

  $form['#validate'][] = 'samlauth_admin_settings_validate';
  $form['#submit'][] = 'samlauth_admin_settings_submit';

  return $form;
}

/**
 * Callback: samlauth_admin_settings().
 *
 * Form validator.
 */
function samlauth_admin_settings_validate(array &$form, array &$form_state) {
  module_load_include('inc', 'samlauth', 'samlauth');

  if (!samlauth_load_private_key($form_state['values']['sp_private_key'])) {
    form_set_error(
      'sp_private_key',
      t('The private key could not be found on the file system.')
    );
  }
}

/**
 * Callback: samlauth_admin_settings().
 *
 * Submit handler.
 */
function samlauth_admin_settings_submit(array &$form, array &$form_state) {
  module_load_include('inc', 'samlauth', 'samlauth');

  samlauth_settings_save('default', $form_state['values']);
}
