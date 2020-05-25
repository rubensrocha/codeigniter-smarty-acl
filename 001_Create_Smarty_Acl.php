<?php
defined('BASEPATH') or exit('No direct script access allowed');

class Migration_Create_Smarty_Acl extends CI_Migration
{
    /**
     * Config settings
     * @var array
     */
    private $settings;

    private function get_settings()
    {
        //Load configs
        $this->config->load('smarty_acl', TRUE);
        //Get tables array
        $tables = $this->config->item('tables', 'smarty_acl');
        //Tables prefix
        $this->settings['prefix'] = $tables['prefix'] ? $tables['prefix'].'_' : '';
        // Table names
        $this->settings['users'] = $tables['users'];
        $this->settings['admins'] = $tables['admins'];
        $this->settings['roles'] = $this->settings['prefix'].$tables['roles'];
        $this->settings['modules'] = $this->settings['prefix'].$tables['modules'];
        $this->settings['module_permissions'] = $this->settings['prefix'].$tables['module_permissions'];
        $this->settings['password_resets'] = $this->settings['prefix'].$tables['password_resets'];
        $this->settings['login_attempts'] = $this->settings['prefix'].$tables['login_attempts'];
    }

    public function up()
    {
        //Load settings
        $this->get_settings();
        /**************** Start Create Tables ****************/
        //Create users
        $this->dbforge->add_field(array(
            'id' => array(
                'type' => 'INT',
                'constraint' => 11,
                'unsigned' => TRUE,
                'auto_increment' => TRUE
            ),
            'username' => array(
                'type' => 'VARCHAR',
                'constraint' => '191',
                'unsigned' => TRUE,
            ),
            'email' => array(
                'type' => 'VARCHAR',
                'constraint' => '191',
                'unsigned' => TRUE,
                'null' => TRUE,
            ),
            'password' => array(
                'type' => 'VARCHAR',
                'constraint' => '191',
            ),
            'name' => array(
                'type' => 'VARCHAR',
                'constraint' => '191',
                'null' => TRUE,
            ),
            'status' => array(
                'type' => 'ENUM',
                'constraint' => ['inactive', 'active', 'banned'],
                'default' => 'active',
            ),
            'ip' => array(
                'type' => 'VARCHAR',
                'constraint' => '191',
            ),
            'last_login' => array(
                'type' => 'timestamp',
                'null' => true,
            ),
            'email_verified_at' => array(
                'type' => 'timestamp',
                'null' => true,
            ),
            'email_activator' => array(
                'type' => 'VARCHAR',
                'constraint' => '255',
                'unsigned' => TRUE,
                'null' => TRUE,
            ),
            'email_activator_code' => array(
                'type' => 'VARCHAR',
                'constraint' => '255',
                'null' => TRUE,
            ),
            'remember_token' => array(
                'type' => 'VARCHAR',
                'constraint' => '255',
                'unsigned' => TRUE,
                'null' => TRUE,
            ),
            'remember_token_code' => array(
                'type' => 'VARCHAR',
                'constraint' => '255',
                'null' => TRUE,
            ),
            'created_at timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP',
            'updated_at timestamp NOT NULL',
        ));
        $this->dbforge->add_key('id', TRUE);
        $this->dbforge->create_table($this->settings['users']);
        //Create admins
        $this->dbforge->add_field(array(
            'id' => array(
                'type' => 'INT',
                'constraint' => 11,
                'unsigned' => TRUE,
                'auto_increment' => TRUE
            ),
            'username' => array(
                'type' => 'VARCHAR',
                'constraint' => '191',
                'unsigned' => TRUE,
            ),
            'email' => array(
                'type' => 'VARCHAR',
                'constraint' => '191',
                'unsigned' => TRUE,
                'null' => TRUE,
            ),
            'role_id' => array(
                'type' => 'int',
                'constraint' => '1',
            ),
            'password' => array(
                'type' => 'VARCHAR',
                'constraint' => '191',
            ),
            'name' => array(
                'type' => 'VARCHAR',
                'constraint' => '191',
                'null' => TRUE,
            ),
            'status' => array(
                'type' => 'ENUM',
                'constraint' => ['inactive', 'active', 'banned'],
                'default' => 'active',
            ),
            'ip' => array(
                'type' => 'VARCHAR',
                'constraint' => '191',
            ),
            'last_login' => array(
                'type' => 'timestamp',
                'null' => true,
            ),
            'email_verified_at' => array(
                'type' => 'timestamp',
                'null' => true,
            ),
            'email_activator' => array(
                'type' => 'VARCHAR',
                'constraint' => '255',
                'unsigned' => TRUE,
                'null' => TRUE,
            ),
            'email_activator_code' => array(
                'type' => 'VARCHAR',
                'constraint' => '255',
                'null' => TRUE,
            ),
            'remember_token' => array(
                'type' => 'VARCHAR',
                'constraint' => '255',
                'unsigned' => TRUE,
                'null' => TRUE,
            ),
            'remember_token_code' => array(
                'type' => 'VARCHAR',
                'constraint' => '255',
                'null' => TRUE,
            ),
            'created_at timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP',
            'updated_at timestamp NOT NULL',
        ));
        $this->dbforge->add_key('id', TRUE);
        $this->dbforge->create_table($this->settings['admins']);
        //Create roles
        $this->dbforge->add_field(array(
            'id' => array(
                'type' => 'INT',
                'constraint' => 11,
                'unsigned' => TRUE,
                'auto_increment' => TRUE
            ),
            'name' => array(
                'type' => 'VARCHAR',
                'constraint' => '191',
            ),
            'status' => array(
                'type' => 'ENUM',
                'constraint' => ['inactive', 'active'],
                'default' => 'active',
            ),
        ));
        $this->dbforge->add_key('id', TRUE);
        $this->dbforge->create_table($this->settings['roles']);
        //Create modules
        $this->dbforge->add_field(array(
            'id' => array(
                'type' => 'INT',
                'constraint' => 11,
                'unsigned' => TRUE,
                'auto_increment' => TRUE
            ),
            'name' => array(
                'type' => 'VARCHAR',
                'constraint' => '191',
            ),
            'controller' => array(
                'type' => 'VARCHAR',
                'constraint' => '191',
            ),
            'permissions' => array(
                'type' => 'JSON',
            ),
        ));
        $this->dbforge->add_key('id', TRUE);
        $this->dbforge->create_table($this->settings['modules']);
        //Create module permissions
        $this->dbforge->add_field(array(
            'id' => array(
                'type' => 'INT',
                'constraint' => 11,
                'unsigned' => TRUE,
                'auto_increment' => TRUE
            ),
            'role_id' => array(
                'type' => 'INT',
                'constraint' => '11',
                'unsigned' => TRUE,
            ),
            'module_id' => array(
                'type' => 'INT',
                'constraint' => '11',
                'unsigned' => TRUE,
            ),
            'permission' => array(
                'type' => 'VARCHAR',
                'constraint' => '191',
            ),
        ));
        $this->dbforge->add_key('id', TRUE);
        $this->dbforge->create_table($this->settings['module_permissions']);
        //Create password resets
        $this->dbforge->add_field(array(
            'id' => array(
                'type' => 'INT',
                'constraint' => 11,
                'unsigned' => TRUE,
                'auto_increment' => TRUE
            ),
            'type' => array(
                'type' => 'ENUM',
                'constraint' => ['admin', 'user'],
                'default' => 'admin',
            ),
            'email' => array(
                'type' => 'VARCHAR',
                'constraint' => '191',
            ),
            'token' => array(
                'type' => 'VARCHAR',
                'constraint' => '191',
            ),
            'token_code' => array(
                'type' => 'VARCHAR',
                'constraint' => '191',
            ),
            'created_at timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP',
        ));
        $this->dbforge->add_key('id', TRUE);
        $this->dbforge->create_table($this->settings['password_resets']);
        //Create login attempts
        $this->dbforge->add_field(array(
            'id' => array(
                'type' => 'INT',
                'constraint' => 11,
                'unsigned' => TRUE,
                'auto_increment' => TRUE
            ),
            'type' => array(
                'type' => 'ENUM',
                'constraint' => ['admin', 'user'],
                'default' => 'admin',
            ),
            'login' => array(
                'type' => 'VARCHAR',
                'constraint' => '191',
            ),
            'ip' => array(
                'type' => 'VARCHAR',
                'constraint' => '191',
            ),
            'created_at timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP',
        ));
        $this->dbforge->add_key('id', TRUE);
        $this->dbforge->create_table($this->settings['login_attempts']);
        /**************** End Create Tables ****************/
        /**************** Start Set Foreign Keys ****************/
        //Foreign keys
        $this->db->query('ALTER TABLE '.$this->settings['module_permissions'].' ADD FOREIGN KEY (role_id) REFERENCES '.$this->settings['roles'].'(id) ON DELETE CASCADE ON UPDATE RESTRICT');
        $this->db->query('ALTER TABLE '.$this->settings['module_permissions'].' ADD FOREIGN KEY (module_id) REFERENCES '.$this->settings['modules'].'(id) ON DELETE CASCADE ON UPDATE RESTRICT');
        //Unique keys
        $this->db->query('ALTER TABLE '.$this->settings['admins'].' ADD UNIQUE (username, email, email_activator, remember_token)');
        $this->db->query('ALTER TABLE '.$this->settings['users'].' ADD UNIQUE (username, email, email_activator, remember_token)');
        /**************** End Set Foreign Keys ****************/
        /**************** Start Insert Data ****************/
        //Default roles
        $this->db->insert($this->settings['roles'],['name' => 'Super Admin']);
        $this->db->insert($this->settings['roles'],['name' => 'Admin']);
        $this->db->insert($this->settings['roles'],['name' => 'Demo']);
        //Default admin
        $this->db->insert($this->settings['admins'],[
             'username' => 'admin',
             'password' => '$2y$10$TmJKG3yV8o7kCycAdQI0/.7jJ5uhO3RC9pyJOMlbFHmbEzUk8JMfu',
             'name' => 'Administrator',
             'email' => 'admin@admin.com',
             'role_id' => 1,
             'status' => 'active',
             'ip' => '172.19.0.1',
             'email_verified_at' => date('Y-m-d H:i:s'),
             'created_at' => date('Y-m-d H:i:s'),
             'updated_at' => date('Y-m-d H:i:s')
        ]);
        /**************** End Insert Data ****************/
    }

    public function down()
    {
        //Load settings
        $this->get_settings();
        //Drop tables
        $this->dbforge->drop_table($this->settings['users']);
        $this->dbforge->drop_table($this->settings['admins']);
        $this->dbforge->drop_table($this->settings['roles']);
        $this->dbforge->drop_table($this->settings['modules']);
        $this->dbforge->drop_table($this->settings['module_permissions']);
        $this->dbforge->drop_table($this->settings['password_resets']);
        $this->dbforge->drop_table($this->settings['login_attempts']);
    }
}