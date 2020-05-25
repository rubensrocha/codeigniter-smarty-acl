<?php
defined('BASEPATH') OR exit('No direct script access allowed');
/**
 * Name:    Smarty ACL Model
 * Author:  Smarty Scripts
 * Site:    https://smartyscripts.com
 *
 * Requirements: PHP7 or above
 */

class Smarty_acl_model extends CI_Model
{
    /**
     * Error messages
     * @var array|string
     */
    private $errors;
    /**
     * General Messages
     * @var array|string
     */
    private $messages;
    /**
     * Error/Message start delimiter
     * @var string
     */
    private $message_start_delimiter;
    /**
     * Error/Message end delimiter
     * @var string
     */
    private $message_end_delimiter;
    /**
     * Table names
     * @var array
     */
    private $tables;

    /**
     * Identity column name
     * @var string
     */
    private $identity;
    /**
     * Default role ID
     * @var int
     */
    private $default_role;
    /**
     * Default password hash algorithm
     * @var string
     */
    private $password_algo;
    /**
     * Session config names
     * @var array
     */
    private $session_names;
    /**
     * Remember cookie names
     * @var array
     */
    private $remember_names;

    public function __construct()
    {
        parent::__construct();
        //Set table names
        $this->set_tables();
        //Set error/messages delimiters
        $this->message_start_delimiter = $this->config->item('message_start_delimiter','smarty_acl');
        $this->message_end_delimiter = $this->config->item('message_end_delimiter','smarty_acl');
        //Set identity column
        $this->identity = $this->config->item('identity','smarty_acl');
        //Set default role ID
        $this->default_role = $this->config->item('default_role','smarty_acl');
        //Set password algo
        $this->password_algo = $this->config->item('password_algo','smarty_acl');
        //Set session names
        $this->session_names = [
            'admin' => $this->config->item('session_name', 'smarty_acl').'_admin_'.sha1(static::class),
            'user' => $this->config->item('session_name', 'smarty_acl').'_user_'.sha1(static::class),
        ];
        //Set remember cookie names
        $this->remember_names = [
            'admin' => $this->config->item('remember_cookie_name', 'smarty_acl').'_admin_'.sha1(static::class),
            'user' => $this->config->item('remember_cookie_name', 'smarty_acl').'_user_'.sha1(static::class),
        ];
    }

    /**
     * Register admin/user
     * @param string $identity
     * @param string $password
     * @param string $email
     * @param array $additional_data
     * @param integer $role_id
     * @param bool $admin
     * @return integer(id) or FALSE
     */
    public function register($identity, $password, $email, $additional_data = [], $role_id = null, $admin = TRUE){
        $table = $admin ? $this->tables['admins'] : $this->tables['users'];
        //Check identity
        if($this->user_exists($identity,$admin)){
            $this->set_error('register_identity_unavailable');
            return FALSE;
        }
        if($admin){
            //Check default role
            if(!$role_id || !$this->default_role){
                $this->set_error('register_undefined_role');
                return FALSE;
            }
            //Check if role exists
            $role_exists = $this->data_exists($this->tables['roles'],'id',$role_id,1);
            if(!$role_exists){
                $this->set_error('register_invalid_role');
                return FALSE;
            }
        }
        // Get IP Address
        $ip_address = $this->input->ip_address();
        // Hash password
        $password = $this->hash_password($password);
        //Filter additional fields
        $additional = $this->filter_data($table, $additional_data);
        //User data
        $user_data = [
            $this->identity => $identity,
            'password' => $password,
            'email' => $email,
            'ip' => $ip_address,
            'created_at' => date('Y-m-d H:i:s'),
            'updated_at' => date('Y-m-d H:i:s'),
        ];
        if($admin){
            $user_data['role_id'] = $role_id;
        }
        //Insert on DB
        $this->db->insert($table, array_merge($user_data, $additional));
        //Get new user ID
        $id = $this->db->insert_id();

        return $id ?? FALSE;
    }

    /**
     * Activate account
     * @param integer $user_id
     * @param string $code
     * @param bool $admin TRUE(admin), FALSE(user)
     * @return bool
     */
    public function activate($user_id, $code, $admin = TRUE)
    {
        if(!$user_id || !$code){
            $this->set_error('activation_invalid_link');
            return FALSE;
        }
        //Retrieve code array
        $token = $this->retrieve_code_pair($code);
        if(!$token){
            $this->set_error('error_invalid_security_token');
            return FALSE;
        }
        //Get user data
        $user_data = $this->get_user_by('email_activator',$token['selector'],$admin);
        if(!$user_data){
            $this->set_error('activation_expired_link');
            return FALSE;
        }
        // Check the hash against the validator
        $validate = password_verify($token['validator'], $user_data['email_activator_code']);
        if(!$validate){
            $this->set_error('activation_invalid_token');
            return FALSE;
        }
        //Activate user
        return $this->update_user([
            'email_activator' => NULL,
            'email_activator_code' => NULL,
            'email_verified_at' => date('Y-m-d H:i:s'),
        ], $user_id, $admin);
    }

    /**
     * Forgot Password
     * @param string $email
     * @param array $token
     * @param bool $admin
     * @return bool|array
     */
    public function forgotten_password($email, $token, $admin = TRUE)
    {
        $type = $admin ? 'admin' : 'user';
        //Get user
        $user = $admin ? $this->get_admin_by_email($email) : $this->get_user_by_email($email);
        if(!$user){
            $this->set_error('forgot_password_email_not_found');
            return FALSE;
        }
        //Data
        $data = [
            'type' => $type,
            'email' => $email,
            'token' => $token['selector'],
            'token_code' => $token['validator_hashed'],
            'created_at' => date('Y-m-d H:i:s')
        ];
        //Check if exists
        $check = $this->db->where('type',$type)->where('email',$email)->count_all_results($this->tables['password_resets']) > 0;
        if($check){
            //Update password_resets table
            $password_reset = $this->db->update($this->tables['password_resets'], $data, ['type' => $type, 'email' => $email]);
        }else{
            //Insert on password_resets table
            $password_reset = $this->db->insert($this->tables['password_resets'], $data);
        }
        if(!$password_reset){
            $this->set_error('error_create_password_reset_data');
            return FALSE;
        }
        return $user;
    }

    /**
     * Forgotten password check
     * @param string $code
     * @param bool $admin
     * @return bool|array
     */
    public function forgotten_password_check($code, $admin = TRUE)
    {
        $table = $admin ? $this->tables['admins'] : $this->tables['users'];
        //Retrieve code array
        $token = $this->retrieve_code_pair($code);
        if(!$token){
            $this->set_error('error_invalid_security_token');
            return FALSE;
        }
        //Get password reset data
        $password = $this->db->where('token', $token['selector'])->get($this->tables['password_resets'])->row();
        if(!$password){
            $this->set_error('password_reset_invalid_token');
            return FALSE;
        }
        //Check expired code
        $expiration = $this->config->item('forgot_password_expiration', 'smarty_acl');
        if($expiration > 0 ){
            $now = date_create();
            $expire = date_create($password->created_at)->modify('+'.$expiration.' sec');
            if ($now > $expire)
            {
                //Delete expired code
                $this->db->delete($this->tables['password_resets'],['token' => $password->token]);
                $this->set_error('password_reset_expired_token');
                return FALSE;
            }
        }
        // Check the hash against the validator
        if (password_verify($token['validator'], $password->token_code))
        {
            //Get user
            $user = $this->db->where('email', $password->email)->get($table)->row_array();
            if(!$user){
                $this->set_error('error_user_not_found');
                return FALSE;
            }
            return $user;
        }
        return FALSE;
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
        $table = $admin ? $this->tables['admins'] : $this->tables['users'];
        //Check user exists
        $user_exists = $this->data_exists($table, 'email', $user['email']);
        if(!$user_exists){
            $this->set_error('error_user_not_found');
            return FALSE;
        }
        //Hash password
        $new_password = $this->hash_password($password);
        //Update user password and email
        $update = $this->update_user([
            'email' => $email,
            'password' => $new_password,
            'remember_token' => null, //invalidate remember token
        ], $user['id'], $admin);
        if(!$update){
            $this->set_error('password_reset_failed_update');
            return FALSE;
        }
        //Remove reset password
        $reset_password = $this->db->delete($this->tables['password_resets'],[
            'type' => $admin ? 'admin' : 'user',
            'email' => $user['email']
        ]);
        if(!$reset_password){
            $this->set_error('password_reset_failed_delete');
            return FALSE;
        }
        return TRUE;
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
        $table = $admin ? $this->tables['admins'] : $this->tables['users'];
        //Count attempts
        $attempts = $this->check_attempts($identity, $admin);
        if(!$attempts){
            return FALSE;
        }
        //Check multi identity login
        $multi = $this->config->item('multi_identity', 'smarty_acl') ? ['email' => $identity] : [$this->identity => $identity];
        //Get user
        $user_data = $this->db->where($this->identity, $identity)->or_where($multi)->limit(1)->get($table)->row();
        //Check role status
        if($admin){
            //Get role
            $role = $this->db->select('status')->where('id',$user_data->role_id)->get($this->tables['roles'])->row();
            //Check status
            if($role->status==='inactive'){
                $this->increase_login_attempts($identity, $admin);
                $this->set_error('login_error_role_inactive');
                return FALSE;
            }
        }
        if(!$user_data){
            $this->increase_login_attempts($identity, $admin);
            $this->set_error('login_error_incorrect');
            return FALSE;
        }
        //Check password
        $check_password = password_verify($password, $user_data->password);
        if(!$check_password){
            $this->increase_login_attempts($identity, $admin);
            $this->set_error('login_error_incorrect');
            return FALSE;
        }
        //Check email verified
        $verified_email = $this->config->item('email_verification', 'smarty_acl');
        if($verified_email && !$user_data->email_verified_at){
            $this->set_error('login_error_email_unverified');
            return FALSE;
        }
        //Check status
        if($user_data->status !== 'active'){
            $this->increase_login_attempts($identity, $admin);
            if($user_data->status === 'inactive'){
                $this->set_error('login_error_account_inactive');
            }
            if($user_data->status === 'banned'){
                $this->set_error('login_error_account_banned');
            }
            return FALSE;
        }
        //Create session
        $this->create_session($user_data->id, $admin);
        //Update user data
        $update_user = $this->update_user(['last_login' => date('Y-m-d H:i:s')], $user_data->id, $admin);
        if(!$update_user){
            $this->set_error('error_update_user_data');
            return FALSE;
        }
        //Clear login attempts
        $clear_attempts = $this->clear_loggin_attempts($identity, $admin);
        if(!$clear_attempts){
            $this->set_error('error_clear_user_attempts');
            return FALSE;
        }
        //Check remember
        if($remember){
            $this->remember_user($user_data->id, $admin);
        }else{
            $this->clear_remember_code($user_data->id, $admin);
        }
        //Regenerate the session (for security purpose: to avoid session fixation)
        $this->session->sess_regenerate(FALSE);
        return TRUE;
    }

    /**
     * Remember user
     * @param int $user_id
     * @param bool $admin
     * @return bool
     */
    public function remember_user($user_id, $admin = TRUE)
    {
        //Cookie name
        $cookie = $admin ? $this->remember_names['admin'] : $this->remember_names['user'];
        //Generate tokens
        $tokens = $this->smarty_acl->generate_selector_validator();
        //Update user tokens
        $update_tokens = $this->security_tokens($user_id,$tokens,'remember',$admin);
        if(!$update_tokens){
            $this->set_error('error_update_security_tokens');
            return FALSE;
        }
        set_cookie([
            'name' => $cookie,
            'value' => $tokens['user_code'],
            'expire' => $this->config->item('session_expire', 'smarty_acl') > 0 ? $this->config->item('session_expire', 'smarty_acl') : 86500
        ]);
        return TRUE;
    }

    /**
     * Clear Remember user
     * @param int $user_id
     * @param bool $admin
     * @return bool
     */
    public function clear_remember_code($user_id, $admin = TRUE)
    {
        return $this->update_user([
        'remember_token' => NULL,
        'remember_token_code' => NULL],$user_id,$admin);
    }

    /**
     * Create user session
     * @param int $user_id
     * @param bool $admin
     * @return bool
     */
    protected function create_session($user_id, $admin = TRUE)
    {
        $table = $admin ? $this->tables['admins'] : $this->tables['users'];
        //Fields
        $fields = $admin ? $this->config->item('session_admin_fields', 'smarty_acl') : $this->config->item('session_user_fields', 'smarty_acl');
        //Filter fields
        $field_keys = array_keys($fields);
        //Customize Column Names
        $custom = implode(', ', array_map(function ($field) use($fields){ return $field.' as '.$fields[$field];},$field_keys));
        //Get user with custom data
        $user = $this->db->select($custom)->where('id', $user_id)->get($table)->row_array();
        //Add last check time and user id with custom key(used by check_session method)
        $session_data = array_merge($user, [
            'acl_uid' => $user_id,
            'last_check' => time()
        ]);
        //Create session
        $this->session->set_userdata($admin ? $this->session_names['admin'] : $this->session_names['user'], $session_data);
        return TRUE;
    }

    /**
     * Get group permissions by role_id
     * @param int $role_id
     * @return array
     */
    public function get_group_permissions_by_role($role_id)
    {
        $modules = $this->db
            ->where('role_id', $role_id)
            ->join($this->tables['module_permissions'] . ' as mp', 'mp.module_id = m.id')
            ->get($this->tables['modules'] . ' as m')->result_array();
        //Mount easy readable array
        $permissions_array = [];
        foreach ($modules as $module) {
            $permissions_array[$module['controller']][] = $module['permission'];
        }
        return $permissions_array;
    }

    /**
     * Clear Login Attempts
     * @param string $identity
     * @param bool $admin
     * @return bool
     */
    private function clear_loggin_attempts($identity, $admin = TRUE)
    {
        return $this->db->delete($this->tables['login_attempts'],['type' => $admin ? 'admin' : 'user', 'login' => $identity]);
    }

    /**
     * Increase Login Attempts
     * @param string $identity
     * @param bool $admin
     * @return bool
     */
    protected function increase_login_attempts($identity, $admin = true)
    {
        if ($this->config->item('maximum_login_attempts', 'smarty_acl') > 0)
        {
            $data = [
                'type' => $admin ? 'admin' : 'user',
                'ip' => $this->input->ip_address(),
                'login' => $identity,
                'created_at' => date('Y-m-d H:i:s')
            ];

            return $this->db->insert($this->tables['login_attempts'], $data);
        }
        return FALSE;
    }

    /**
     * Check login attempts
     * @param string $identity
     * @param bool $admin
     * @return bool
     */
    protected function check_attempts($identity, $admin = true)
    {
        //Get configs
        $max = $this->config->item('maximum_login_attempts', 'smarty_acl');
        $lockout_time = $this->config->item('lockout_time', 'smarty_acl');
        $time = date_create()->modify('-'.$lockout_time.' sec');
        //Check if max attempts equals 0(disabled)
        if($max === 0) {
            return TRUE;
        }
        //Count attempts
        $attempts = $this->rows_count($this->tables['login_attempts'],['login' => $identity, 'type' => $admin ? 'admin' : 'user', 'created_at >' => $time->format('Y-m-d H:i:s')]);
        if($attempts >= $max){
            $this->set_error('login_error_timeout');
            return FALSE;
        }
        return TRUE;
    }

    /**
     * Check session for logged in user
     * @param bool $admin
     * @return bool
     */
    public function session_check($admin = TRUE)
    {
        //Get session name
        $session_name = $admin ? $this->session_names['admin'] : $this->session_names['user'];
        $session = $this->session->userdata($session_name);
        //Check session exists
        if(!$session){
            return FALSE;
        }
        //Get recheck
        $recheck = $this->config->item('session_recheck', 'smarty_acl');
        if($recheck === 0){
            return TRUE;
        }
        //Recheck session
        if($session['last_check'] + $recheck > time()){
            return TRUE;
        }
        $table_name = $admin ? $this->tables['admins'] : $this->tables['users'];
        $find_where = ['id' => $session['acl_uid'], 'status' => 'active'];
        if($this->config->item('email_verification', 'smarty_acl')){
            $find_where['email_verified_at !='] = NULL;
        }
        //Find user
        $user = $this->db->where($find_where)->limit(1)->count_all_results($table_name);
        if(!$user){
            //Unset session
            $this->session->unset_userdata($session_name);
            return FALSE;
        }
        return TRUE;
    }

    /**
     * Login user using remember cookie
     * @param bool $admin
     * @return bool
     */
    public function login_remembered($admin = TRUE)
    {
        //Get cookie name
        $cookie_name = $admin ? $this->remember_names['admin'] : $this->remember_names['user'];
        $cookie = get_cookie($cookie_name);
        if(!$cookie){
            return FALSE;
        }
        //Get token
        $token = $this->retrieve_code_pair($cookie);
        if(!$token){
            $this->set_error('error_invalid_security_token');
            return FALSE;
        }
        //Check user exists and delete cookie
        $table_name = $admin ? $this->tables['admins'] : $this->tables['users'];
        $find_where = ['remember_token' => $token['selector'], 'status' => 'active'];
        if($this->config->item('email_verification', 'smarty_acl')){
            $find_where['email_verified_at !='] = NULL;
        }
        //Find user
        $user = $this->db->where($find_where)->limit(1)->get($table_name)->row();
        if(!$user){
            $this->set_error('error_user_not_found');
            delete_cookie($cookie_name);
            return FALSE;
        }
        //Validate token
        if (!password_verify($token['validator'], $user->remember_token_code))
        {
            return FALSE;
        }
        //Set session
        $this->create_session($user->id, $admin);
        //Update user data
        $update_user = $this->update_user(['last_login' => date('Y-m-d H:i:s')], $user->id, $admin);
        if(!$update_user){
            $this->set_error('error_update_user_data');
            return FALSE;
        }
        //Clear login attempts
        $clear_attempts = $this->clear_loggin_attempts($user->{$this->identity}, $admin);
        if(!$clear_attempts){
            $this->set_error('error_clear_user_attempts');
            return FALSE;
        }
        // Regenerate the session (for security purpose: to avoid session fixation)
        $this->session->sess_regenerate(FALSE);
        return TRUE;
    }

    /**
     * Logout user
     * @param bool $admin
     * @return bool
     */
    public function logout($admin = TRUE)
    {
        //Get session name
        $session_name = $admin ? $this->session_names['admin'] : $this->session_names['user'];
        //Delete user session
        $this->session->unset_userdata($session_name);
        //Get cookie name
        $cookie_name = $admin ? $this->remember_names['admin'] : $this->remember_names['user'];
        //Delete cookie
        delete_cookie($cookie_name);
        //Delete remember tokens
        $this->clear_remember_code($this->session->userdata($session_name)['acl_uid'],$admin);
        // Destroy the session
        $this->session->sess_destroy();
        return true;
    }

    /**
     * Get Roles
     * @param bool $result
     * @return object|array
     */
    public function roles($result = TRUE){
        $results = $result ? 'result' : 'result_array';
        return $this->db->get($this->tables['roles'])->{$results}();
    }

    /**
     * Create role
     * @param array $data
     * @return bool
     */
    public function create_role($data)
    {
        $fields = $this->filter_data($this->tables['roles'],$data);
        $create = $this->db->insert($this->tables['roles'],$fields);
        if(!$create){
            $this->set_error('roles_error_unable_create');
            return FALSE;
        }
        //Assign permissions
        $new_role = $this->db->insert_id();
        return $this->permissions_to_role($new_role,$data['permissions']);
    }

    /**
     * Update roles
     * @param int $role_id
     * @param array $data
     * @return bool
     */
    public function update_role($role_id,$data)
    {
        $fields = $this->filter_data($this->tables['roles'],$data);
        //Check superadmin role, avoid disable
        if($role_id == 1){
            $fields['status'] = 'active';
        }
        $update = $this->db->update($this->tables['roles'],$fields,['id' => $role_id]);
        if(!$update){
            $this->set_error('roles_error_unable_update');
            return FALSE;
        }
        //Assign permissions
        return $this->permissions_to_role($role_id,$data['permissions']);
    }

    /**
     * Delete role
     * @param int $role_id
     * @return bool
     */
    public function delete_role($role_id)
    {
        //Check superadmin role
        if($role_id == 1){
            $this->set_error('roles_error_notallowed_delete');
            return FALSE;
        }
        //Move users to default role
        $default_role = $this->config->item('default_role', 'smarty_acl');
        $this->db->where('role_id',$role_id)->update($this->tables['admins'],['role_id' => $default_role]);
        //Delete role
        return $this->db->delete($this->tables['roles'],['id' => $role_id]);
    }
    /**
     * Assoc permissions to role
     * @param int $role_id
     * @param array $permissions
     * @return bool
     */
    private function permissions_to_role($role_id,$permissions)
    {
        //Get module ids
        $get_modules = array_keys($permissions);
        //Delete module permissions not checked
        $this->db->where('role_id', $role_id)->where_not_in('module_id',$get_modules)->delete($this->tables['module_permissions']);
        foreach ($permissions as $module => $permission){
            //Get permissions values
            $get_permissions = array_values($permission);
            if($get_permissions){
                $this->db->where(['module_id' => $module, 'role_id' => $role_id])->where_not_in('permission',$get_permissions)->delete($this->tables['module_permissions']);
                //Create
                array_map(function ($a) use($module, $role_id) {
                    //Check if exists
                    $exists = $this->db->where(['module_id' => $module, 'role_id' => $role_id, 'permission' => $a])->count_all_results($this->tables['module_permissions']) > 0;
                    if(!$exists) {
                        //Insert permission
                        $this->db->where(['module_id' => $module, 'role_id' => $role_id])->where('permission !=', $a)->insert($this->tables['module_permissions'], ['role_id' => $role_id, 'module_id' => $module, 'permission' => $a]);
                        return ['module_id' => $module, 'permission' => $a];
                    }
                }, $permission);
            }
        }
        return TRUE;
    }

    /**
     * Get modules
     * @param bool $result
     * @return object|array
     */
    public function modules($result = TRUE)
    {
        $results = $result ? 'result' : 'result_array';
        return $this->db->get($this->tables['modules'])->{$results}();
    }

    /**
     * Get admins
     * @param bool $result
     * @return object|array
     */
    public function admins($result = TRUE)
    {
        $results = $result ? 'result' : 'result_array';
        return $this->db->select('r.name as group_name, u.*')
            ->join($this->tables['admins'].' as u', 'u.role_id = r.id','inner')
            ->get($this->tables['roles'].' as r')->{$results}();
    }

    /**
     * Get users
     * @param bool $result
     * @return object|array
     */
    public function users($result = TRUE)
    {
        $results = $result ? 'result' : 'result_array';
        return $this->db->get($this->tables['users'])->{$results}();
    }

    /**
     * Get module permissions
     * @param int $role_id
     * @param bool $result
     * @return object|array
     */
    public function module_permissions($role_id, $result = TRUE)
    {
        $results = $result ? 'result' : 'result_array';
        $permissions = $this->db->where('role_id',$role_id)->get($this->tables['module_permissions'])->{$results}();
        $result = [];
        if($permissions) {
            foreach ($permissions as $p) {
                $result[$p['module_id']][$p['id']] = $p['permission'];
            }
        }
        return $result;
    }

    /**
     * Create module
     * @param array $data
     * @return bool
     */
    public function create_module($data)
    {
        $fields = $this->filter_data($this->tables['modules'],$data);
        //Remove whitespaces
        $permissions = str_replace(' ','',$data['permissions']);
        //Convert to json array
        $fields['permissions'] = json_encode(explode(',',$permissions));
        $create = $this->db->insert($this->tables['modules'],$fields);
        if(!$create){
            $this->set_error('modules_error_unable_create');
            return FALSE;
        }
        return TRUE;
    }

    /**
     * Update module
     * @param int $module_id
     * @param array $data
     * @return bool
     */
    public function update_module($module_id, $data)
    {
        $fields = $this->filter_data($this->tables['modules'],$data);
        //Remove whitespaces
        $permissions = str_replace(' ','',$data['permissions']);
        //Convert to json array
        $fields['permissions'] = json_encode(explode(',',$permissions));
        $update = $this->db->update($this->tables['modules'],$fields,['id' => $module_id]);
        if(!$update){
            $this->set_error('modules_error_unable_update');
            return FALSE;
        }
        return TRUE;
    }

    /**
     * Delete module
     * @param int $module_id
     * @return bool
     */
    public function delete_module($module_id)
    {
        //Delete module
        return $this->db->delete($this->tables['modules'],['id' => $module_id]);
    }

    /**
     * Get session name
     * @return array
     */
    public function get_session_names()
    {
        return $this->session_names;
    }

    /**
     * Get admin user by ID
     * @param string $user_id
     * @return array
     */
    public function get_admin_by_id($user_id = NULL)
    {
        //Get session name
        $session_name = $this->session_names['admin'];
        $user = $user_id ?? $this->session->userdata($session_name)['acl_uid'];
        return $this->get_user_by('id', $user);
    }

    /**
     * Get admin user by email
     * @param string $user_email
     * @return array
     */
    public function get_admin_by_email($user_email)
    {
        return $this->get_user_by('email', $user_email);
    }

    /**
     * Get user by ID
     * @param string $user_id
     * @return array
     */
    public function get_user_by_id($user_id = NULL)
    {
        //Get session name
        $session_name = $this->session_names['user'];
        $user = $user_id ?? $this->session->userdata($session_name)['acl_uid'];
        return $this->get_user_by('id', $user, FALSE);
    }

    /**
     * Get user by email
     * @param string $user_email
     * @return array
     */
    public function get_user_by_email($user_email)
    {
        return $this->get_user_by('email', $user_email, FALSE);
    }

    /**
     * Get user or admin by id
     * @param string $field
     * @param string $value
     * @param bool $admin
     * @return array
     */
    private function get_user_by($field, $value, $admin = true)
    {
        $table = $admin ? $this->tables['admins'] : $this->tables['users'];
        //Add group name on array
        if($admin){
            return $this->db->select('r.name as group_name, u.*')
                ->where('u.'.$field, $value)
                ->join($table.' as u', 'u.role_id = r.id','inner')
                ->get($this->tables['roles'].' as r')->row_array();
        }
        return $this->db->where($field, $value)->get($table)->row_array();
    }

    /**
     * Update user security tokens
     * @param integer $user_id
     * @param array $tokens
     * @param string $type activation / remember
     * @param bool $role admin / user
     * @return bool
     */
    public function security_tokens($user_id, $tokens, $type = 'activation', $role = TRUE)
    {
        $table = $role ? $this->tables['admins'] : $this->tables['users'];
        if($type==='remember'){
            $data = [
                'remember_token' => $tokens['selector'],
                'remember_token_code' => $tokens['validator_hashed']
            ];
        }else{
            $data = [
                'email_activator' => $tokens['selector'],
                'email_activator_code' => $tokens['validator_hashed']
            ];
            //Check if user already verified email
            $check = $this->db->where('email_verified_at !=',null)->where('id',$user_id)->count_all_results($table) > 0;
            if($check){
                $this->set_error('error_email_already_confirmed');
                return FALSE;
            }
        }
        $update = $this->update_user($data, $user_id, $role);
        if(!$update){
            $this->set_error('error_update_security_tokens');
            return FALSE;
        }
        return TRUE;
    }

    /**
     * Update user data
     * @param array $data
     * @param integer $user_id
     * @param bool $admin
     * @return bool
     */
    public function update_user($data, $user_id, $admin = true)
    {
        $table = $admin ? $this->tables['admins'] : $this->tables['users'];
        $new_data = array_merge($data, ['updated_at' => date('Y-m-d H:i:s')]);
        $updated = $this->db->update($table, $new_data, ['id' => $user_id]);
        if(!$updated){
            $this->set_error('error_updating_user_account');
            return FALSE;
        }
        return TRUE;
    }

    /**
     * Delete user
     * @param int $user_id
     * @param bool $admin
     * @return bool
     */
    public function delete_user($user_id, $admin = TRUE)
    {
        $table = $admin ? $this->tables['admins'] : $this->tables['users'];
        //Set session name
        $session_name = $admin ? $this->session_names['admin'] : $this->session_names['user'];
        //Legged in user
        $loggedin_user = $this->session->userdata($session_name);
        //Avoid delete yourself
        if($user_id == $loggedin_user['acl_uid']){
            $this->set_error('error_user_delete_yourself');
            return FALSE;
        }
        //Admin checks
        if($admin){
            $get_admin = $this->get_admin_by_id($user_id);
            $get_loggedin_admin = $this->get_admin_by_id($loggedin_user['acl_uid']);
            //Avoid other roles delete superadmin
            if($get_admin['role_id'] == 1 && $get_loggedin_admin['role_id'] != 1){
                $this->set_error('error_admin_delete_superadmin');
                return FALSE;
            }
        }
        //Delete user
        return $this->db->delete($table,['id' => $user_id]);
    }

    /**
     * Return validator code pair for activation and remember me
     * @param string $code
     * @return array|bool
     */
    private function retrieve_code_pair($code)
    {
        if($code){
            $token = explode('.',$code);
            // Check tokens
            if (count($token) === 2)
            {
                return [
                    'selector' => $token[0],
                    'validator' => $token[1]
                ];
            }
        }
        return FALSE;
    }

    /**
     * Filter additional fields array
     * @param string $table
     * @param array  $data
     * @return array
     */
    protected function filter_data($table, $data)
    {
        $filtered_data = [];
        $columns = $this->db->list_fields($table);

        if (is_array($data))
        {
            foreach ($columns as $column)
            {
                if (array_key_exists($column, $data)) {
                    $filtered_data[$column] = $data[$column];
                }
            }
        }
        return $filtered_data;
    }

    /**
     * Create a password hash
     * @param string $password
     * @return string
     */
    public function hash_password($password)
    {
        return password_hash($password, $this->password_algo);
    }

    /**
     * Check if user already registered
     * @param string $identity
     * @param bool $type admin / user
     * @return bool
     */
    public function user_exists($identity, $type = TRUE){
        if(!$identity){
            return FALSE;
        }
        $table = $type ? $this->tables['admins'] : $this->tables['users'];
        return $this->data_exists($table,$this->identity,$identity,1);
    }

    /**
     * Check if data exists on a table
     * @param $table_name string
     * @param $field string
     * @param $value string
     * @param $limit integer
     * @return bool
     */
    private function data_exists($table_name, $field, $value, $limit = null)
    {
        return $this->db->where($field, $value)
                ->limit($limit)
                ->count_all_results($table_name) > 0;
    }

    /**
     * Count rows
     * @param string $table
     * @param array $params
     * @return integer
     */
    protected function rows_count($table, $params = null)
    {
        if($params){
            $this->db->where($params);
        }
        return $this->db->get($table)->num_rows();
    }

    /**
     * Set table names with/without prefix
     */
    private function set_tables()
    {
        $tables = $this->config->item('tables','smarty_acl');
        $prefix = $tables['prefix'] ? $tables['prefix'].'_' : '';
        $this->tables = [
            'admins' => $tables['admins'],
            'users' => $tables['users'],
            'roles' => $prefix.$tables['roles'],
            'modules' => $prefix.$tables['modules'],
            'module_permissions' => $prefix.$tables['module_permissions'],
            'password_resets' => $prefix.$tables['password_resets'],
            'login_attempts' => $prefix.$tables['login_attempts'],
        ];
    }

    /**
     * Set error message
     * @param string $error
     * @return string
     */
    public function set_error($error)
    {
        $this->errors[] = $error;
        return $error;
    }

    /**
     * Get error messages
     * @param bool $translate
     * @return string|array
     */
    public function errors($translate = TRUE)
    {
        return $this->get_errors_messages(TRUE, $translate);
    }

    /**
     * Set a message
     * @param string $message
     * @return string
     */
    public function set_message($message)
    {
        $this->messages[] = $message;
        return $message;
    }

    /**
     * Get messages
     * @param bool $translate
     * @return string|array
     */
    public function messages($translate = TRUE)
    {
        return $this->get_errors_messages(FALSE, $translate);
    }

    /**
     * Return errors or message response
     * @param bool $error
     * @param bool $translate
     * @return string|array messages/errors translated or messages/errors as array
     */
    private function get_errors_messages($error = TRUE, $translate = TRUE)
    {
        $values = $error ? $this->errors : $this->messages;
        if ($translate)
        {
            $_output = [];
            foreach ($values as $value)
            {
                $errorLang = $this->lang->line($value) ?? '##' . $value . '##';
                $_output[] = $this->message_start_delimiter . $errorLang . $this->message_end_delimiter;
            }
            if(count($_output) >= 2){
                return $_output;
            }
            return $_output[0];
        }
        return $values;
    }
    /**
     * Set the message delimiters
     * @param string $start_delimiter
     * @param string $end_delimiter
     * @return bool
     */
    public function set_message_delimiters($start_delimiter, $end_delimiter)
    {
        $this->message_start_delimiter = $start_delimiter;
        $this->message_end_delimiter   = $end_delimiter;
        return TRUE;
    }
}