<?php
defined('BASEPATH') or exit('No direct script access allowed');
/**
 * Name:    Smarty ACL Config
 * Author:  Smarty Scripts
 * Site:    https://smartyscripts.com
 *
 * Requirements: PHP7 or above
 */

/*
| -------------------------------------------------------------------------
| Tables Prefixes
| -------------------------------------------------------------------------
| Prefix or ''(empty). Used in all tables, except admins and users
| Default: acl
*/
$config['tables']['prefix'] = 'acl';
/*
| -------------------------------------------------------------------------
| Tables
| -------------------------------------------------------------------------
| Database table names.
*/
$config['tables']['users'] = 'users'; //Separate table for ordinary users(without ACL)
$config['tables']['admins'] = 'admins'; //Admin users table name
$config['tables']['roles'] = 'roles'; //Roles(groups) table name
$config['tables']['modules'] = 'modules'; //Modules(controllers) table name
$config['tables']['module_permissions'] = 'module_permissions'; //Module permissions table
$config['tables']['password_resets'] = 'password_resets'; //Password resets table
$config['tables']['login_attempts'] = 'login_attempts'; //Login attempts table
/*
| -------------------------------------------------------------------------
| Email Verification
| -------------------------------------------------------------------------
| Enable/disable email verification
| Default: FALSE
*/
$config['email_verification'] = TRUE;
/*
| -------------------------------------------------------------------------
| Email Sender
| -------------------------------------------------------------------------
| Send Email using the builtin CI email class, if false it will return the code and the user data
| Default: TRUE
*/
$config['email_sender'] = TRUE;
/*
| -------------------------------------------------------------------------
| Sender Email Address
| -------------------------------------------------------------------------
| Send Email using this address
| Default: any@yoursite.com
*/
$config['sender_email'] = 'any@yoursite.com';
/*
| -------------------------------------------------------------------------
| Sender Name
| -------------------------------------------------------------------------
| Sender Name
| Default: any@yoursite.com
*/
$config['sender_name'] = 'YourSite.com';
/*
| -------------------------------------------------------------------------
| Email Settings
| -------------------------------------------------------------------------
| Email settings array
*/
$config['email_settings'] = [
    'smtp_host' => 'smtp.mailtrap.io', // your smtp host url
    'smtp_port' => '2525', // your smtp host port(outgoing). Eg.: 465, 587
    'smtp_user' => '', // your smtp username
    'smtp_pass' => '', // your smtp password
    'smtp_crypto' => 'NULL', // SSL, TLS, NULL
    'protocol' => 'smtp', // mail protocol. smtp, sendmail, mail
    'charset' => 'utf-8', // charset
    'mailtype' => 'html', // text or html
    'crlf' => "\r\n", //Newline character. (Use “\r\n” to comply with RFC 822).
    'newline' => "\r\n", //Newline character. (Use “\r\n” to comply with RFC 822).
];
/*
 | -------------------------------------------------------------------------
 | Email templates
 | -------------------------------------------------------------------------
 | Folder where email templates are stored.
 | Default: auth/email/
 */
$config['email_templates'] = 'auth/email/';
/*
 | -------------------------------------------------------------------------
 | Identity
 | -------------------------------------------------------------------------
 | The values in this column, alongside password, will be used for login purposes
 | Default: username
 */
$config['identity'] = 'username';
/*
 | -------------------------------------------------------------------------
 | Multi Identity
 | @param bool FALSE(identity only)
 | @param string column_name(identity or column_name)
 | -------------------------------------------------------------------------
 | Allows login using only the identity or email as optional.
 | Eg: Login with username or email on same field
 | Default: FALSE
 */
$config['multi_identity'] = FALSE;
/*
 | -------------------------------------------------------------------------
 | Default Role
 | -------------------------------------------------------------------------
 | Default role id assigned to register new admin user
 | Default: 2 (admin group)
 */
$config['default_role'] = 2;
/*
 | -------------------------------------------------------------------------
 | Default Unauthorized Route
 | -------------------------------------------------------------------------
 | Default route name for unauthorized access
 | Default:
 */
$config['unauthorized_route'] = 'unauthorized';
/*
 | -------------------------------------------------------------------------
 | Error and Messages Delimiters
 | -------------------------------------------------------------------------
 | ''(empty) or html element. <p>, <span>, <li>, etc
 */
$config['message_start_delimiter'] = ''; // Message start delimiter
$config['message_end_delimiter']   = ''; // Message end delimiter
/*
 | -------------------------------------------------------------------------
 | Password algorithm
 | -------------------------------------------------------------------------
 | Default algorithm to hash password
 | Default: PASSWORD_BCRYPT
 */
$config['password_algo'] = PASSWORD_BCRYPT;
/*
 | -------------------------------------------------------------------------
 | Forgot Password Expiration
 | -------------------------------------------------------------------------
 | The number of seconds after which a forgot password request will expire. If set to 0, forgot password requests will not expire.
 | Default: 1800 (30 min)
 */
$config['forgot_password_expiration'] = 1800;
/*
 | -------------------------------------------------------------------------
 | Min Password Length
 | -------------------------------------------------------------------------
 | Minimum Required Length of Password (not enforced by lib, use this with form validation)
 | Default: 6
 */
$config['min_password_length'] = 6;
/*
 | -------------------------------------------------------------------------
 | Max Login Attempts
 | -------------------------------------------------------------------------
 | The maximum number of failed login attempts.
 | Default: 3
 */
$config['maximum_login_attempts'] = 3;
/*
 | -------------------------------------------------------------------------
 | Login Lockout Time
 | -------------------------------------------------------------------------
 | The number of seconds to lockout an account due to exceeded attempts. You should not use a value below 60 (1 minute)
 | Default: 600 (10 min)
*/
$config['lockout_time'] = 600;
/*
 | -------------------------------------------------------------------------
 | Session Expiration Time
 | -------------------------------------------------------------------------
 | How long to remember the user (seconds). Set to zero for no expiration - see sess_expiration in CodeIgniter Session config for session expiration
 | Default: 86400 (24 hours)
*/
$config['session_expire'] = 86400;
/*
 | -------------------------------------------------------------------------
 | Session Recheck Time
 | -------------------------------------------------------------------------
 | The number of seconds after which the session is checked again against database to see if the user still exists and is active. Leave 0 if you don't want session recheck
 | Default: 0
*/
$config['session_recheck'] = 0;
/*
 | -------------------------------------------------------------------------
 | Remember Cookie Prefix Name
 | -------------------------------------------------------------------------
 | Remember cookie prefix name.
 | Default: 'remember' Return: remember_admin_(hash) for admin users / remember_user_(hash) for common users
*/
$config['remember_cookie_name'] = 'remember';
/*
 | -------------------------------------------------------------------------
 | Session Prefix Name
 | -------------------------------------------------------------------------
 | Admin session prefix name
 | Default: 'login' Return: login_admin_(hash) for admin users / login_user_(hash) for users
*/
$config['session_name'] = 'login';
/*
 | -------------------------------------------------------------------------
 | Session Admin Fields
 | -------------------------------------------------------------------------
 | Admin fields to store on session. You can set a custom name for each item using the second parameter.
 | column name(db) => key name(session)
*/
$config['session_admin_fields'] = [
    'id' => 'user_id',
    'username' => 'username',
    'email' => 'email',
    'name' => 'name',
    'role_id' => 'role_id', //necessary for group permissions checks
];
/*
 | -------------------------------------------------------------------------
 | Session User Fields
 | -------------------------------------------------------------------------
 | User fields to store on session. You can set a custom name for each item using the second parameter.
 | column name(db) => key name(session)
*/
$config['session_user_fields'] = [
    'id' => 'id',
    'username' => 'username',
    'email' => 'email',
    'name' => 'name',
];
/*
 | -------------------------------------------------------------------------
 | Cache settings
 | -------------------------------------------------------------------------
 | Caches group and module data for better performance. Updating groups or modules clears the cache automatically.
 | Drivers: apc, file, memcached, wincache, redis
*/
$config['cache_settings'] = [
    'status' => FALSE, // TRUE,FALSE enable/disable cache
    'time' => 300, //Time To Live, in seconds. 300 = 5 min
    'driver' => 'memcached', //primary driver
    'driver_fallback' => 'file', //fall back driver
];