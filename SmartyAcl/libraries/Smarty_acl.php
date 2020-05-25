<?php
defined('BASEPATH') or exit('No direct script access allowed');
/**
 * Name:    Smarty ACL Library
 * Author:  Smarty Scripts
 * Site:    https://smartyscripts.com
 *
 * Requirements: PHP7 or above
 */

class Smarty_acl
{
    /**
     * Codeigniter instance
     * @var $CI object
     */
    private $CI;
    /**
     * Identity column name
     * @var string
     */
    private $identity;
    /**
     * Session names (admins and users)
     * @var array
     */
    private $sess_names;
    /**
     * Cache settings
     * @var array
     */
    private $cache_settings;

    public function __construct()
    {
        //Get Codeigniter instance
        $this->CI =& get_instance();
        //Load necessary libraries and helpers
        $this->CI->load->library('session');
        $this->CI->load->helper('cookie');
        $this->CI->load->helper('url');
        //DB Connection
        $this->CI->load->database();
        //Load lang, config and model
        $this->CI->lang->load('smarty_acl');
        $this->CI->load->config('smarty_acl', TRUE);
        $this->CI->load->model('smarty_acl_model', 'smartyacl_model');
        //Get identity
        $this->identity = $this->CI->config->item('identity', 'smarty_acl');
        //Cache settings
        $this->cache_settings = $this->CI->config->item('cache_settings', 'smarty_acl');
        if ($this->cache_settings['status'] === TRUE) {
            $this->CI->load->driver('cache', array('adapter' => $this->cache_settings['driver'], 'backup' => $this->cache_settings['driver_fallback']));
        }
        //Set session names
        $this->set_session_names();
    }

    /**
     * Register
     *
     * @param string $identity
     * @param string $password
     * @param string $email
     * @param array $additional_data
     * @param integer $role_id
     *
     * @return int|array|bool The new user's ID if e-mail activation is disabled or
     * Ion-Auth e-mail activation was completed;
     * or an array of activation details if CI e-mail validation is enabled;
     * or FALSE if the operation failed.
     * @throws Exception
     */
    public function register($identity, $password, $email, $additional_data = [], $role_id = null)
    {
        //Use defined role or default role
        $role_id = $role_id ?? $this->CI->config->item('default_role', 'smarty_acl');
        //Create user
        $create = $this->CI->smartyacl_model->register($identity, $password, $email, $additional_data, $role_id);

        if ($create) {
            //Check for activation email
            if ($this->CI->config->item('email_verification', 'smarty_acl')) {
                //Generate activation token
                return $this->request_activation($email);
            }
            return TRUE;
        }
        return FALSE;
    }

    /**
     * Register user
     *
     * @param string $identity
     * @param string $password
     * @param string $email
     * @param array $additional_data
     *
     * @return int|array|bool The new user's ID if e-mail activation is disabled or
     * Ion-Auth e-mail activation was completed;
     * or an array of activation details if CI e-mail validation is enabled;
     * or FALSE if the operation failed.
     * @throws Exception
     */
    public function register_user($identity, $password, $email, $additional_data = [])
    {
        //Create user
        $create = $this->CI->smartyacl_model->register($identity, $password, $email, $additional_data,NULL,FALSE);

        if ($create) {
            //Check for activation email
            if ($this->CI->config->item('email_verification', 'smarty_acl')) {
                //Generate activation token
                return $this->request_activation($email,FALSE);
            }
            return TRUE;
        }
        return FALSE;
    }

    /**
     * Request activation
     * @param string $email
     * @param bool $admin
     * @param bool $result_array
     * @return bool|array
     * @throws Exception
     */
    private function request_activation($email, $admin = TRUE, $result_array = FALSE)
    {
        if (!$email) {
            return FALSE;
        }
        //Get user data
        if ($admin) {
            $user = $this->CI->smartyacl_model->get_admin_by_email($email);
        } else {
            $user = $this->CI->smartyacl_model->get_user_by_email($email);
        }
        if (!$user) {
            $this->set_error('error_user_not_found');
            return FALSE;
        }
        //Generate activation token
        $tokens = $this->generate_selector_validator(20, 40);
        //Update user security tokens
        $update_tokens = $this->CI->smartyacl_model->security_tokens($user['id'], $tokens,'activation',$admin);
        if (!$update_tokens) {
            return FALSE;
        }
        //Get user data
        $user_data = [
            'identity' => $user[$this->identity],
            'id' => $user['id'],
            'email' => $user['email'],
            'activation' => $tokens['user_code']
        ];
        //Check if email_sender is active or request_array was set
        if ($result_array || !$this->CI->config->item('email_sender', 'smarty_acl')) {
            return $user_data;
        }
        //Send activation email
        return $this->send_activation_email($user_data, $tokens['user_code'], $admin);
    }

    /**
     * Send activation mail
     * @param array $user_data
     * @param string $activation
     * @param bool $admin
     * @return bool
     */
    public function send_activation_email($user_data, $activation = null, $admin = TRUE)
    {
        if (!$user_data) {
            return FALSE;
        }
        if ($activation) {
            $user_data = array_merge($user_data, ['activation' => $activation]);
        }
        return $this->send_mail($user_data, 'activation', $admin);
    }

    /**
     * Send mail to user
     * @param array $data
     * @param string $type
     * @param bool $admin
     * @return bool
     */
    private function send_mail($data, $type, $admin = TRUE)
    {
        //Load helpers for email template
        $this->CI->load->helper('language');
        $this->CI->load->helper('url');

        if ($type === 'activation') {
            $subject = $this->CI->config->item('sender_name', 'smarty_acl') . ' - ' . $this->CI->lang->line('email_activation_subject');
            $view_name = $admin ? 'admin/activate' : 'user/activate';
            //Message view template
            $message = $this->CI->load->view($this->CI->config->item('email_templates', 'smarty_acl') . $view_name, $data, TRUE);
        }
        if ($type === 'password') {
            $subject = $this->CI->config->item('sender_name', 'smarty_acl') . ' - ' . $this->CI->lang->line('email_forgotten_password_subject');
            $view_name = $admin ? 'admin/forgot_password' : 'user/forgot_password';
            //Message view template
            $message = $this->CI->load->view($this->CI->config->item('email_templates', 'smarty_acl') . $view_name, $data, TRUE);
        }
        //Load email library
        $this->CI->load->library('email');
        //Config email
        $this->CI->email->initialize($this->CI->config->item('email_settings', 'smarty_acl'));

        $this->CI->email->clear();
        $this->CI->email->from($this->CI->config->item('sender_email', 'smarty_acl'), $this->CI->config->item('sender_name', 'smarty_acl'));
        $this->CI->email->to($data['email']);
        $this->CI->email->subject($subject);
        $this->CI->email->message($message);

        if ($this->CI->email->send() === TRUE) {
            return TRUE;
        }
        $this->set_error($this->CI->email->print_debugger(array('headers', 'subject', 'body')));
        return FALSE;
    }

    /**
     * Activate admin user account
     * @param integer $user_id
     * @param string $code
     * @return bool
     */
    public function activate($user_id, $code)
    {
        return $this->CI->smartyacl_model->activate($user_id, $code);
    }

    /**
     * Activate user account
     * @param integer $user_id
     * @param string $code
     * @return bool
     */
    public function activate_user($user_id, $code)
    {
        return $this->CI->smartyacl_model->activate($user_id, $code, FALSE);
    }

    /**
     * Resend activation link
     * @param string $email
     * @param bool $admin
     * @return bool
     * @throws Exception
     */
    public function resend_activation($email, $admin = TRUE)
    {
        if (!$email) {
            return FALSE;
        }
        return $this->request_activation($email, $admin);
    }

    /**
     * Forgot Password
     * @param string $email
     * @param bool $admin
     * @return bool
     * @throws Exception
     */
    public function forgotten_password($email, $admin = TRUE)
    {
        //Generate activation token
        $tokens = $this->generate_selector_validator(20, 40);
        //Create password reset
        $result = $this->CI->smartyacl_model->forgotten_password($email, $tokens, $admin);
        //Password reset created
        if ($result) {
            $data = [
                'identity' => $result[$this->identity],
                'email' => $email,
                'forgotten_password_code' => $tokens['user_code'],
            ];
            //Send forgot password email
            return $this->send_mail($data, 'password', $admin);
        }
        return FALSE;
    }

    /**
     * Check forgot password code
     * @param string $code
     * @param bool $admin
     * @return bool|array
     */
    public function forgotten_password_check($code, $admin = TRUE)
    {
        //Get user
        $user = $this->CI->smartyacl_model->forgotten_password_check($code, $admin);
        if (!$user) {
            return FALSE;
        }
        return $user;
    }

    /**
     * Reset password
     * @param array $user
     * @param string $email
     * @param string $password
     * @param bool $admin
     * @return bool
     */
    public function reset_password($user, $email, $password, $admin = TRUE)
    {
        return $this->CI->smartyacl_model->reset_password($user, $email, $password, $admin);
    }

    /**
     * Login
     * @param string $identity
     * @param string $password
     * @param bool $remember
     * @param bool $admin
     * @return bool
     */
    public function login($identity, $password, $remember = FALSE, $admin = TRUE)
    {
        return $this->CI->smartyacl_model->login($identity, $password, $remember, $admin);
    }

    /**
     * Check if user is logged in
     * @param bool $admin
     * @return bool
     */
    public function logged_in($admin = TRUE)
    {
        $logged = $this->CI->smartyacl_model->session_check($admin);
        //Try login using remember
        if (!$logged) {
            return $this->CI->smartyacl_model->login_remembered($admin);
        }
        return TRUE;
    }

    /**
     * Logout
     * @param bool $admin
     * @return bool
     */
    public function logout($admin = TRUE)
    {
        return $this->CI->smartyacl_model->logout($admin);
    }

    /**
     * Get roles
     * @param bool $result
     * @return object|array
     */
    public function roles($result = TRUE)
    {
        //Cache
        $cache_name = $this->CI->config->item('tables', 'smarty_acl')['roles'];
        if ($this->cache_settings['status']) {
            if (!$roles = $this->cache_get($cache_name)) {
                $roles = $this->CI->smartyacl_model->roles($result);
                $this->cache_save($cache_name, $roles);
            }
            return $roles;
        }
        return $this->CI->smartyacl_model->roles($result);
    }

    /**
     * Create role
     * @param array $data
     * @return bool
     */
    public function create_role($data)
    {
        $created = $this->CI->smartyacl_model->create_role($data);
        if ($created) {
            //Clear cache
            $this->cache_delete($this->CI->config->item('tables', 'smarty_acl')['roles']);
            $this->cache_delete('group_permissions');
            return TRUE;
        }
        return FALSE;
    }

    /**
     * Get role
     * @param int $role_id
     * @return object|bool
     */
    public function role($role_id)
    {
        $roles = $this->roles();
        foreach ($roles as $key => $value) {
            if ($value->id === $role_id) {
                return $value;
            }
        }
        return FALSE;
    }

    /**
     * Update role
     * @param bool $role_id
     * @param array $data
     * @return bool
     */
    public function update_role($role_id, $data)
    {
        $updated = $this->CI->smartyacl_model->update_role($role_id, $data);
        if ($updated) {
            //Clear cache
            $this->cache_delete($this->CI->config->item('tables', 'smarty_acl')['roles']);
            $this->cache_delete('group_permissions');
            return TRUE;
        }
        return FALSE;
    }

    /**
     * Delete role
     * @param bool $role_id
     * @return bool
     */
    public function delete_role($role_id)
    {
        $deleted = $this->CI->smartyacl_model->delete_role($role_id);
        if ($deleted) {
            //Clear cache
            $this->cache_delete($this->CI->config->item('tables', 'smarty_acl')['roles']);
            return TRUE;
        }
        return FALSE;
    }

    /**
     * Get modules
     * @param bool $result
     * @return object|array
     */
    public function modules($result = TRUE)
    {
        //Cache
        if ($this->cache_settings['status']) {
            if (!$modules = $this->cache_get($this->CI->config->item('tables', 'smarty_acl')['modules'])) {
                $modules = $this->CI->smartyacl_model->modules($result);
                $this->cache_save($this->CI->config->item('tables', 'smarty_acl')['modules'], $modules);
            }
            return $modules;
        }
        return $this->CI->smartyacl_model->modules($result);
    }

    /**
     * Get module permissions
     * @param int $role_id
     * @param bool $result
     * @return object|array
     */
    public function module_permissions($role_id, $result = FALSE)
    {
        return $this->CI->smartyacl_model->module_permissions($role_id, $result);
    }

    /**
     * Create module
     * @param array $data
     * @return bool
     */
    public function create_module($data)
    {
        $created = $this->CI->smartyacl_model->create_module($data);
        if ($created) {
            //Clear cache
            $this->cache_delete($this->CI->config->item('tables', 'smarty_acl')['modules']);
            return TRUE;
        }
        return FALSE;
    }

    /**
     * Get module
     * @param int $module_id
     * @return object|bool
     */
    public function module($module_id)
    {
        $modules = $this->modules();
        foreach ($modules as $key => $value) {
            if ($value->id === $module_id) {
                return $value;
            }
        }
        return FALSE;
    }

    /**
     * Update module
     * @param bool $module_id
     * @param array $data
     * @return bool
     */
    public function update_module($module_id, $data)
    {
        $updated = $this->CI->smartyacl_model->update_module($module_id, $data);
        if ($updated) {
            //Clear cache
            $this->cache_delete($this->CI->config->item('tables', 'smarty_acl')['modules']);
            return TRUE;
        }
        return FALSE;
    }

    /**
     * Delete module
     * @param bool $module_id
     * @return bool
     */
    public function delete_module($module_id)
    {
        $deleted = $this->CI->smartyacl_model->delete_module($module_id);
        if ($deleted) {
            //Clear cache
            $this->cache_delete($this->CI->config->item('tables', 'smarty_acl')['modules']);
            return TRUE;
        }
        return FALSE;
    }

    /**
     * Check if user is authorized
     * Use on constructor of Controllers, or default method
     * @return bool|void
     */
    public function authorized()
    {
        //Check if super admin
        if($this->CI->session->userdata($this->sess_names['admin'])['role_id'] == 1){
            return TRUE;
        }
        //Get module
        $module = $this->CI->uri->segment(2);
        //Authorized if user is on admin/ route
        if(!$module){
            return TRUE;
        }
        //Check module permissions
        $group_permissions = $this->module_authorized($module);
        if($group_permissions){
            return TRUE;
        }
        //Unauthorized
        return $this->unauthorized_redirect();
    }

    /**
     * Check if user has module permission access
     * Can be used on views
     * @param string $module
     * @return bool
     */
    public function module_authorized($module)
    {
        //Check if super admin
        if($this->CI->session->userdata($this->sess_names['admin'])['role_id'] == 1){
            return TRUE;
        }
        //Default class method name
        $permission = 'index';
        //Get logged in user group permissions
        $group_permissions = $this->get_group_permissions_by_role();
        if(!$group_permissions){ return show_error($this->errors()); }
        //Check authorization
        return isset($group_permissions[$module]) && in_array($permission, $group_permissions[$module]);
    }

    /**
     * Check if user is authorized on module action
     * Use on constructor of Controllers, or default method
     * @return bool|void
     */
    public function authorized_action()
    {
        //Check if super admin
        if($this->CI->session->userdata($this->sess_names['admin'])['role_id'] == 1){
            return TRUE;
        }
        //Get module
        $action = $this->CI->uri->segment(3);
        //Authorized if user is on admin/ route
        if($action){
            //Check module permissions
            $group_permissions = $this->has_permission($action);
            if($group_permissions){
                return TRUE;
            }
        }

        //Unauthorized
        return $this->unauthorized_redirect();
    }

    /**
     * Check if user has module action permission access
     * Can be used on views
     * @param string $permission
     * @return bool
     */
    public function has_permission($permission)
    {
        //Check if super admin
        if($this->CI->session->userdata($this->sess_names['admin'])['role_id'] == 1){
            return TRUE;
        }
        //Default class method name
        $module = $this->CI->uri->segment(2);
        //Get logged in user group permissions
        $group_permissions = $this->get_group_permissions_by_role();
        if(!$group_permissions){ return show_error($this->errors()); }
        //Check authorization
        return isset($group_permissions[$module]) && in_array($permission, $group_permissions[$module]);
    }

    /**
     * Redirect unauthorized access
     * @return void
     */
    private function unauthorized_redirect()
    {
        $route = $this->CI->config->item('unauthorized_route', 'smarty_acl');
        return redirect($route);
    }

    /**
     * Get group permissions
     * @return array|bool
     */
    private function get_group_permissions_by_role()
    {
        $role_id = $this->CI->session->userdata($this->sess_names['admin'])['role_id'];
        //Check if user is logged in and have role_id on session array
        if(!$role_id){
            $this->set_error('error_loggedin_role_id_not_found');
            return FALSE;
        }
        //Cache with role_id to avoid conflict with other role groups
        $cache_name = 'group_permissions_'.$role_id;
        if ($this->cache_settings['status']) {
            if (!$group_permissions = $this->cache_get($cache_name)) {
                $group_permissions = $this->CI->smartyacl_model->get_group_permissions_by_role($role_id);
                $this->cache_save($cache_name, $group_permissions);
            }
            return $group_permissions;
        }
        return $this->CI->smartyacl_model->get_group_permissions_by_role($role_id);
    }

    /**
     * Get admins
     * @param bool $result
     * @return object|array
     */
    public function admins($result = TRUE)
    {
        return $this->CI->smartyacl_model->admins($result);
    }

    /**
     * Get users
     * @param bool $result
     * @return object|array
     */
    public function users($result = TRUE)
    {
        return $this->CI->smartyacl_model->users($result);
    }

    /**
     * Update user account
     * @param array $data
     * @param int $user_id
     * @param bool $admin
     * @return bool
     */
    public function update_user($data, $user_id, $admin = TRUE)
    {
        //Check for password
        if(isset($data['password'])){
            $data['password'] = $this->hash_password($data['password']);
        }
        $updated = $this->CI->smartyacl_model->update_user($data, $user_id, $admin);
        if($updated){
            //Cache Delete
            if ($this->cache_settings['status']) {
                $cache_name = $admin ? 'admin_'.$user_id : 'user_'.$user_id;
                if ($this->cache_get($cache_name)) {
                    $this->cache_delete($cache_name);
                    return TRUE;
                }
                return TRUE;
            }
            return TRUE;
        }
        return FALSE;
    }

    /**
     * Delete user account
     * @param int $user_id
     * @param bool $admin
     * @return bool
     */
    public function delete_user($user_id, $admin = TRUE)
    {
        $deleted = $this->CI->smartyacl_model->delete_user($user_id, $admin);
        if($deleted){
            //Cache Delete
            if ($this->cache_settings['status']) {
                $cache_name = $admin ? 'admin_'.$user_id : 'user_'.$user_id;
                if ($this->cache_get($cache_name)) {
                    $this->cache_delete($cache_name);
                    return TRUE;
                }
                return TRUE;
            }
            return TRUE;
        }
        return FALSE;
    }

    /**
     * Get user by id
     * @param int $user_id
     * @param bool $admin
     * @return array
     */
    public function get_user($user_id = NULL, $admin = FALSE)
    {
        //Set session name
        $session_name = $admin ? $this->sess_names['admin'] : $this->sess_names['user'];
        //Get logged in user
        $loggedin_user = $this->CI->session->userdata($session_name);
        //Get user_id or set using session data
        $id_user = $user_id ?? $loggedin_user['acl_uid'];
        //Set cache name
        $cache_name = $admin ? 'admin_'.$id_user : 'user_'.$id_user;
        if($admin){
            //Cache
            if ($this->cache_settings['status'] && isset($loggedin_user) && $loggedin_user['acl_uid'] === $id_user) {
                if (!$user_loggedin = $this->cache_get($cache_name)) {
                    $user_loggedin = $this->CI->smartyacl_model->get_admin_by_id($id_user);
                    $this->cache_save($cache_name, $user_loggedin);
                }
                return $user_loggedin;
            }
            return $this->CI->smartyacl_model->get_admin_by_id($id_user);
        }
        //Cache
        if ($this->cache_settings['status'] && isset($loggedin_user) && $loggedin_user['acl_uid'] === $id_user) {
            if (!$user_loggedin = $this->cache_get($cache_name)) {
                $user_loggedin = $this->CI->smartyacl_model->get_user_by_id($id_user);
                $this->cache_save($cache_name, $user_loggedin);
            }
            return $user_loggedin;
        }
        return $this->CI->smartyacl_model->get_user_by_id($id_user);
    }

    /**
     * Get admin user by id
     * @param $user_id
     * @return array
     */
    public function get_admin($user_id= NULL)
    {
        return $this->get_user($user_id, TRUE);
    }

    /**
     * Delete cache items
     * @param string $item
     * @return bool
     */
    protected function cache_delete($item)
    {
        if ($this->cache_settings['status']) {
            $prefix = $this->CI->config->item('tables', 'smarty_acl')['prefix'];
            $name = $prefix . '_' . $item;
            return $this->CI->cache->delete($name);
        }
        return TRUE;
    }

    /**
     * Save cache items
     * @param string $name
     * @param string|array $values
     * @return bool
     */
    protected function cache_save($name, $values)
    {
        if ($this->cache_settings['status']) {
            $prefix = $this->CI->config->item('tables', 'smarty_acl')['prefix'];
            $name = $prefix . '_' . $name;
            return $this->CI->cache->save($name, $values, $this->cache_settings['time']);
        }
        return TRUE;
    }

    /**
     * Get cache items
     * @param string $name
     * @return bool|object
     */
    protected function cache_get($name)
    {
        if ($this->cache_settings['status']) {
            $prefix = $this->CI->config->item('tables', 'smarty_acl')['prefix'];
            $name = $prefix . '_' . $name;
            return $this->CI->cache->get($name);
        }
        return TRUE;
    }

    /**
     * Generate email/remember tokens and selectors
     * @param $selector_size int    size of the selector token
     * @param $validator_size int    size of the validator token
     *
     * @return array
     *            selector            simple token to retrieve the user (to store in DB)
     *            validator_hashed    token (hashed) to validate the user (to store in DB)
     *            user_code            code to be used user-side (in cookie or URL)
     * @throws Exception
     */
    public function generate_selector_validator($selector_size = 40, $validator_size = 128)
    {
        // The selector is a simple token to retrieve the user
        $selector = $this->random_token($selector_size);

        // The validator will strictly validate the user and should be more complex
        $validator = $this->random_token($validator_size);

        // The validator is hashed for storing in DB (avoid session stealing in case of DB leaked)
        $validator_hashed = $this->hash_password($validator);

        // The code to be used user-side
        $user_code = "$selector.$validator";

        return [
            'selector' => $selector,
            'validator_hashed' => $validator_hashed,
            'user_code' => $user_code,
        ];
    }

    /**
     * Generate a random token
     * @param int $result_length
     * @return string
     * @throws Exception
     */
    protected function random_token($result_length = 32)
    {
        if (!$result_length || $result_length <= 8) {
            $result_length = 32;
        }

        return bin2hex(random_bytes($result_length / 2));
    }

    /**
     * Get errors
     * @return string|array
     */
    public function errors()
    {
        return $this->CI->smartyacl_model->errors();
    }

    /**
     * Get messages
     * @return string|array
     */
    public function messages()
    {
        return $this->CI->smartyacl_model->messages();
    }

    /**
     * Set error message
     * @param string $error
     * @return string
     */
    public function set_error($error)
    {
        return $this->CI->smartyacl_model->set_error($error);
    }

    /**
     * Set message
     * @param string $message
     * @return string
     */
    public function set_message($message)
    {
        return $this->CI->smartyacl_model->set_message($message);
    }

    /**
     * Set error/message delimiters
     * @param int $start
     * @param int $end
     * @return bool
     */
    public function set_delimiter($start, $end)
    {
        return $this->CI->smartyacl_model->set_message_delimiters($start, $end);
    }

    /**
     * Hash passwords
     * @param string $password
     * @return string
     */
    public function hash_password($password)
    {
        return $this->CI->smartyacl_model->hash_password($password);
    }

    /**
     * Set session names
     */
    private function set_session_names()
    {
        $this->sess_names = $this->CI->smartyacl_model->get_session_names();
    }
}
