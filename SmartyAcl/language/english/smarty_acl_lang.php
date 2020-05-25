<?php if (!defined('BASEPATH')) exit('No direct script access allowed');
/**
 * Name:    Smarty ACL Error Messages
 * Author:  Smarty Scripts
 * Site:    https://smartyscripts.com
 */

// General Errors
$lang['error_update_security_tokens'] = 'Unable to update user security tokens';
$lang['error_update_user_data'] = 'Unable to update user data';
$lang['error_clear_user_attempts'] = 'Unable to clear user attempts';
$lang['error_user_not_found'] = 'User not found';
$lang['error_invalid_security_token'] = 'Invalid security token code';
$lang['error_email_already_confirmed'] = 'Email address has already been confirmed';
$lang['error_loggedin_role_id_not_found'] = 'User Role ID not found';
$lang['error_updating_user_account'] = 'Unable to update user account data';
$lang['error_user_delete_yourself'] = 'You can not delete your own account';
$lang['error_admin_delete_superadmin'] = 'You are not authorized to delete this type of user.';

// Register
$lang['register_identity_unavailable'] = 'Identity already used or invalid';
$lang['register_undefined_role'] = 'Default role is not set';
$lang['register_invalid_role'] = 'Default role is not valid';

//Activation Email
$lang['email_activation_subject'] = 'Account Activation';
$lang['email_activate_heading'] = 'Activate account for %s';
$lang['email_activate_subheading'] = 'Please click this link to %s.';
$lang['email_activate_link'] = 'Activate Your Account';

//Activation
$lang['activation_invalid_link'] = 'Empty or invalid activation link';
$lang['activation_expired_link'] = 'Expired or invalid activation link';
$lang['activation_invalid_token'] = 'The account could not be activated with this code. Request a new activation link.';

//Forgotten Password
$lang['forgot_password_email_not_found'] = 'Unable to find an account with this email address';
$lang['error_create_password_reset_data'] = 'Unable to create password reset data';

// Forgot Password Email
$lang['email_forgotten_password_subject'] = 'Forgotten Password Verification';
$lang['email_forgot_password_heading'] = 'Reset Password for %s';
$lang['email_forgot_password_subheading'] = 'Please click this link to %s.';
$lang['email_forgot_password_link'] = 'Reset Your Password';

//Reset password
$lang['password_reset_invalid_token'] = 'Unable to find reset password code';
$lang['password_reset_expired_token'] = 'Expired reset password code';
$lang['password_reset_failed_update'] = 'Unable to update your account password';
$lang['password_reset_failed_delete'] = 'Unable to delete reset password data';

//Login
$lang['login_error_incorrect'] = 'Incorrect Login or Password';
$lang['login_error_timeout'] = 'Temporarily Locked Out. Try again later.';
$lang['login_error_role_inactive'] = 'Your group is inactive, you cannot continue with login.';
$lang['login_error_account_inactive'] = 'Inactive account, you cannot continue with login.';
$lang['login_error_account_banned'] = 'Account banned, you cannot continue with login.';
$lang['login_error_email_unverified'] = 'Before proceeding, please check your email for a verification link.';

//Roles
$lang['roles_error_unable_create'] = 'Unable to create new Role';
$lang['roles_error_unable_update'] = 'Unable to update Role';
$lang['roles_error_unable_delete'] = 'Unable to update Role';
$lang['roles_error_notallowed_delete'] = 'Can\'t delete the administrators\' group';

//Modules
$lang['modules_error_unable_create'] = 'Unable to create new Module';
$lang['modules_error_unable_update'] = 'Unable to update Module';
$lang['modules_error_unable_delete'] = 'Unable to update Module';