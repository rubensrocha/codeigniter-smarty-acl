
## Smarty ACL
SmartyACL is a library with basic authentication and authorization functions for Codeigniter 3. This library was based on Ion Auth but with the addition of ACL / RBAC and some other features.
  
### Features
- Register
  - Register admin or user
  - Send mail verification (optional)
- Login
  - Single or Multi login(email, username or both) 
  - Limit max attempts
  - Remember me
  - Checks account status(inactive or banned) (optional)
  - Check mail verification (optional)
- Forgot Password
  - Send reset password mail
- Reset Password
  - Validate security code and update user email/password
- Roles
  - Create, update, delete
  - Assign module permissions
- Modules
  - Create, update and delete
- Admin Group - Users with role/permission access
- User Group - Common users without role/permission access
- Cache data to improve performance (optional)
  
### Summary
- [Requirements](#requirements)
- [Demo](#demo)
- [Installation](#installation)
- [Default Login](#default-login)
- [Usage](#usage)
- [Contributing](#contributing)
- [Support](#support)
- [References](#references)
  
### Requirements
- Codeigniter 3 (developed on 3.1.11)
- PHP 7.x (developed on 7.3)

### Demo
Download a demo application [here](https://github.com/rubensrocha/codeigniter-smarty-acl-demo)  

### Installation
1. Download latest released version
2. Put SmartyAcl folder on `application/third_party` directory
3. Add to `$autoload['packages']`¹ in `application/config/autoload.php`
    ```
    $autoload['packages'] = array(APPPATH.'third_party/SmartyAcl');
    ```
4. Import DB tables using migration or database.sql file
5. Config library preferences on `application/third_party/SmartyAcl/config/smarty_acl.php`

¹ Alternatively, you can copy the contents of the SmartyAcl folder to the respective directories in the application folder and load the library directly into the controller using `$this->load->library('smarty_acl');`

### Default Login
Username: admin<br>
Password: 123456
### Usage
Methods List

| Method | Description |
| :----- | :------- |
| [register()](#register-admin) | Register a new Admin User |
| [register_user()](#register-user) | Register a new User |
| [login()](#login) | User or Admin Login |
| [activate()](#activate-admin-or-user) | Activate admin user with code(email) |
| [activate_user()](#activate-admin-or-user) | Activate user with code(email) |
| [resend_activation()](#resend-activation-mail) | Resend email confirmation code (admin/user) |
| [forgotten_password()](#forgotten-password) | Send reset password email (admin/user) |
| [forgotten_password_check()](#forgotten-password-check) | Validate forgotten password code (admin/user) |
| [reset_password()](#reset-password) | Reset email and password (admin/user) |
| [logged_in()](#logged-in) | Check if user is logged in (admin/user) |
| [logout()](#logout) | Logout current logged in user (admin/user) |
| [roles()](#get-roles) | Get roles list |
| [role()](#get-role) | Get single role |
| [create_role()](#create-role) | Create a new Role |
| [update_role()](#update-role) | Update a single Role |
| [delete_role()](#delete-role) | Delete a single Role |
| [modules()](#get-modules) | Get modules list |
| [module()](#get-module) | Get single module |
| [create_module()](#create-module) | Create a new Module |
| [update_module()](#update-module) | Update a single Module |
| [delete_module()](#delete-module) | Delete a single Module |
| [module_permissions()](#get-module-permissions) | Get a single Module Permissions |
| [authorized()](#authorized) | Check if logged in user is authorized to access current module |
| [module_authorized()](#module-authorized) | Check if logged in user has permission to a specific  module |
| [authorized_action()](#authorized-module-action) | Check if logged in user has permission to current  module action method |
| [has_permission()](#has-permission) | Check if logged in user has permission to a specific  module action method |
| [admins()](#get-admins) | Get admins |
| [users()](#get-users) | Get users |
| [get_user()](#get-user) | Get a single user |
| [get_admin()](#get-admin) | Get a single admin |
| [update_user()](#update-user) | Update a single user (admin/user) |
| [delete_user()](#delete-user) | Delete a single user (admin/user) |
| [set_delimiter()](#errors-delimiters) | Set delimiters for error messages |
| [errors()](#error-messages) | Show error messages |

#### Register Admin
Call:
```php
$this->smarty_acl->register($identity, $password, $email, $additional_data, $role_id);
```
Responses:
```
int = user registered
array = user data array if verification is enabled but 'email_sender' is disabled
false(bool) = failed to register
``` 

| Field | Required | Info |
| :-----: | :--------: | :-------: |
| $identity | yes | field used to register/login user (username, email, phone, etc) |
| $password | yes | user password |
| $email | yes | user email address |
| $additional_data | no | array with additional data(name, address, country, etc) (optional) |
| $role_id | no | role id to assign(optional). If null, will use `$config['default_role']` |

#### Register User
Call:
```php
$this->smarty_acl->register_user($identity, $password, $email, $additional_data, $role_id);
```
Responses:
```
int = user registered
array = user data array if verification is enabled but 'email_sender' is disabled
false(bool) = failed to register
``` 

| Field | Required | Info |
| :-----: | :--------: | :-------: |
| $identity | yes | field used to register/login user (username, email, phone, etc) |
| $password | yes | user password |
| $email | yes | user email address |
| $additional_data | no | array with additional data(name, address, country, etc) (optional) |

#### Login
Call:
```php
$this->smarty_acl->login($identity, $password, $remember, $admin);
```
Response:
```
(bool) = true if logged in
``` 

| Field | Required | Info |
| :-----: | :--------: | :-------: |
| $identity | yes | field used to register/login user (username, email, phone, etc) |
| $password | yes | user password |
| $admin | no (default TRUE) | (bool) set FALSE to user login |

#### Activate Admin or user
Call:
```php
//Admin user
$this->smarty_acl->activate($user_id, $code);
//User
$this->smarty_acl->activate_user($user_id, $code);
```
Response:
```
(bool) = true if activated
``` 

| Field | Required | Info |
| :-----: | :--------: | :-------: |
| $user_id | yes | User ID |
| $code | yes | Activation Security Code |

#### Resend Activation Mail
Call:
```php
$this->smarty_acl->resend_activation($email, $admin);
```
Response:
```
(bool) = true if sent successfully
``` 

| Field | Required | Info |
| :-----: | :--------: | :-------: |
| $email | yes | User email address |
| $admin | no (default TRUE) | (bool) set FALSE to use for users |

#### Forgotten Password
Call:
```php
$this->smarty_acl->forgotten_password($email, $admin);
```
Response:
```
(bool) = true if sent successfully
``` 

| Field | Required | Info |
| :-----: | :--------: | :-------: |
| $email | yes | User email address |
| $admin | no (default TRUE) | (bool) set FALSE to use for users |

#### Forgotten Password Check
Call:
```php
$this->smarty_acl->forgotten_password_check($code, $admin);
```
Response:
```
(bool) = false if code is invalid or expired
(array) = user data array
``` 

| Field | Required | Info |
| :-----: | :--------: | :-------: |
| $code | yes | Secret Code |
| $admin | no (default TRUE) | (bool) set FALSE to use for users |

#### Reset Password
Call:
```php
$this->smarty_acl->reset_password($user, $email, $password, $admin);
```
Response:
```
(bool) = true if updated successfully
``` 

| Field | Required | Info |
| :-----: | :--------: | :-------: |
| $user | yes | Array with current user data(from forgotten_password_check()) |
| $email | yes | New email address |
| $password | yes | New password |
| $admin | no (default TRUE) | (bool) set FALSE to use for users |

#### Logged in
Call:
```php
$this->smarty_acl->logged_in($admin);
```
Response:
```
(bool) = true if user is logged in
``` 

| Field | Required | Info |
| :-----: | :--------: | :-------: |
| $admin | no (default TRUE) | (bool) set FALSE to use for users |

#### Logout
Call:
```php
$this->smarty_acl->logout($admin);
```
Response:
```
(bool) = true if user is logged out
``` 

| Field | Required | Info |
| :-----: | :--------: | :-------: |
| $admin | no (default TRUE) | (bool) set FALSE to use for users |

#### Get Roles
Call:
```php
$this->smarty_acl->roles($result);
```
Response:
```
Roles list as object or array
``` 

| Field | Required | Info |
| :-----: | :--------: | :-------: |
| $result | no (default TRUE) | (bool) set FALSE to return array |

#### Create Role
Call:
```php
$this->smarty_acl->create_role($data);
```
Response:
```
(bool) = true if created
``` 

| Field | Required | Info |
| :-----: | :--------: | :-------: |
| $data | yes | array with role fields/values |

#### Get Role
Call:
```php
$this->smarty_acl->role($role_id);
```
Response:
```
(object) = if found
(bool) = false if not found
``` 

| Field | Required | Info |
| :-----: | :--------: | :-------: |
| $role_id | yes | Role ID |

#### Update Role
Call:
```php
$this->smarty_acl->update_role($role_id, $data);
```
Response:
```
(bool) = true if updated
``` 

| Field | Required | Info |
| :-----: | :--------: | :-------: |
| $role_id | yes | Role ID |
| $data | yes | array with role fields/values |

#### Delete Role
Call:
```php
$this->smarty_acl->delete_role($role_id);
```
Response:
```
(bool) = true if deleted
``` 

| Field | Required | Info |
| :-----: | :--------: | :-------: |
| $role_id | yes | Role ID |

#### Get Modules
Call:
```php
$this->smarty_acl->modules($result);
```
Response:
```
Roles list as object or array
``` 

| Field | Required | Info |
| :-----: | :--------: | :-------: |
| $result | no (default TRUE) | (bool) set FALSE to return array |

#### Create Module
Call:
```php
$this->smarty_acl->create_module($data);
```
Response:
```
(bool) = true if created
``` 

| Field | Required | Info |
| :-----: | :--------: | :-------: |
| $data | yes | array with module fields/values |

#### Get Module
Call:
```php
$this->smarty_acl->module($module_id);
```
Response:
```
(object) = if found
(bool) = false if not found
``` 

| Field | Required | Info |
| :-----: | :--------: | :-------: |
| $role_id | yes | Role ID |

#### Update Module
Call:
```php
$this->smarty_acl->update_module($module_id, $data);
```
Response:
```
(bool) = true if updated
``` 

| Field | Required | Info |
| :-----: | :--------: | :-------: |
| $role_id | yes | Role ID |
| $data | yes | array with module fields/values |

#### Delete Module
Call:
```php
$this->smarty_acl->delete_module($module_id);
```
Response:
```
(bool) = true if deleted
``` 

| Field | Required | Info |
| :-----: | :--------: | :-------: |
| $role_id | yes | Role ID |

#### Get Module Permissions
Call:
```php
$this->smarty_acl->module_permissions($role_id);
```
Response:
```
(array) = multidimensional array with
{
    [module_id] => {
        [permission_id] => [permission_method_name]
    }
}
``` 

| Field | Required | Info |
| :-----: | :--------: | :-------: |
| $role_id | yes | Role ID |

#### Authorized
Call:
```php
$this->smarty_acl->authorized();
```
Response:
```
redirect to unathorized route if not authorized
```

#### Module Authorized
Call:
```php
$this->smarty_acl->module_authorized($module);
```
Response:
```
(bool) = false if not authorized
``` 

| Field | Required | Info |
| :-----: | :--------: | :-------: |
| $module | yes | Module Controller Name |

#### Authorized Module Action
Call:
```php
$this->smarty_acl->authorized_action();
```
Response:
```
redirect to unathorized route if not authorized
```

#### Has Permission
Call:
```php
$this->smarty_acl->has_permission($permission);
```
Response:
```
(bool) = false if not authorized
``` 

| Field | Required | Info |
| :-----: | :--------: | :-------: |
| $permission | yes | Module Permission Name |

#### Get Admins
Call:
```php
$this->smarty_acl->admins($result);
```
Response:
```
Admins list as object or array
``` 

| Field | Required | Info |
| :-----: | :--------: | :-------: |
| $result | no (default TRUE) | (bool) set FALSE to return array |

#### Get Users
Call:
```php
$this->smarty_acl->users($result);
```
Response:
```
Users list as object or array
``` 

| Field | Required | Info |
| :-----: | :--------: | :-------: |
| $result | no (default TRUE) | (bool) set FALSE to return array |

#### Get User
Call:
```php
$this->smarty_acl->get_user($user_id);
```
Response:
```
User data as array
``` 

| Field | Required | Info |
| :-----: | :--------: | :-------: |
| $user_id | yes | User ID |

#### Get Admin
Call:
```php
$this->smarty_acl->get_admin($user_id);
```
Response:
```
Admin data as array
``` 

| Field | Required | Info |
| :-----: | :--------: | :-------: |
| $user_id | yes | User ID |

#### Update User
Call:
```php
$this->smarty_acl->update_user($data, $user_id, $admin);
```
Response:
```
(bool) = true if updated
``` 

| Field | Required | Info |
| :-----: | :--------: | :-------: |
| $data | yes | array with user fields/values |
| $user_id | yes | User ID |
| $admin | no (default TRUE) | (bool) set FALSE to use for users |

#### Delete User
Call:
```php
$this->smarty_acl->delete_user($user_id,$admin);
```
Response:
```
(bool) = true if deleted
``` 

| Field | Required | Info |
| :-----: | :--------: | :-------: |
| $user_id | yes | User ID |
| $admin | no (default TRUE) | (bool) set FALSE to use for users |

#### Errors Delimiters
Call:
```php
$this->smarty_acl->set_delimiter($start, $end);
```
Response:
```
(bool) = true if set successfully
``` 

| Field | Required | Info |
| :-----: | :--------: | :-------: |
| $start | yes | Start delimiter (`<p>,<li>,<span>`, etc) |
| $end | yes | End delimiter (`</p>,</li>,</span>`, etc) |

#### Error Messages
Call:
```php
$this->smarty_acl->errors();
```
Response:
```
(string) = for single error
(array) = for multiple errors
``` 

### Contributing
Feel free to contribute with corrections, optimizations or improvements. Just send a [Pull Request](https://github.com/rubensrocha/codeigniter-smarty-acl/pulls) with your contribution.
### Support
If you found a bug, [Create an Issue](https://github.com/rubensrocha/codeigniter-smarty-acl/issues).
If you're having an issue with CodeIgniter or for general help with development I recommend checking out the [CodeIgniter Forums](http://forum.codeigniter.com/)
### References
- [Ion Auth](https://github.com/benedmunds/CodeIgniter-Ion-Auth) repository used as reference
