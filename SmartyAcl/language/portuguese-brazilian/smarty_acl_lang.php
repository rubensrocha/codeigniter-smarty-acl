<?php if (!defined('BASEPATH')) exit('No direct script access allowed');
/**
 * Name:    Smarty ACL Error Messages
 * Author:  Smarty Scripts
 * Site:    https://smartyscripts.com
 */

// General Errors
$lang['error_update_security_tokens'] = 'Não foi possível atualizar os tokens de segurança do usuário';
$lang['error_update_user_data'] = 'Não foi possível atualizar os dados do usuário';
$lang['error_clear_user_attempts'] = 'Não foi possível limpar as tentativas do usuário';
$lang['error_user_not_found'] = 'Usuário não encontrado';
$lang['error_invalid_security_token'] = 'Código de token de segurança inválido';
$lang['error_email_already_confirmed'] = 'O endereço de email já foi confirmado';
$lang['error_loggedin_role_id_not_found'] = 'ID da função de usuário não encontrado';
$lang['error_updating_user_account'] = 'Não foi possível atualizar os dados da conta do usuário';
$lang['error_user_delete_yourself'] = 'Você não pode excluir sua própria conta';
$lang['error_admin_delete_superadmin'] = 'Você não está autorizado a excluir este tipo de usuário.';
$lang['error_admin_unable_send_mail'] = 'Não foi possível enviar o e-mail! Verifique os logs para obter mais informações.';

// Register
$lang['register_identity_unavailable'] = 'Identidade já usada ou inválida';
$lang['register_undefined_role'] = 'A função padrão não está definida';
$lang['register_invalid_role'] = 'A função padrão não é válida';

//Activation Email
$lang['email_activation_subject'] = 'Ativação de Conta';
$lang['email_activate_heading'] = 'Ativar de conta para %s';
$lang['email_activate_subheading'] = 'Clique neste link para %s.';
$lang['email_activate_link'] = 'Ativar sua Conta';

//Activation
$lang['activation_invalid_link'] = 'Link de ativação vazio ou inválido';
$lang['activation_expired_link'] = 'Link de ativação expirado ou inválido';
$lang['activation_invalid_token'] = 'Não foi possível ativar a conta com este código. Solicite um novo link de ativação.';

//Forgotten Password
$lang['forgot_password_email_not_found'] = 'Não foi possível encontrar uma conta com este endereço de e-mail';
$lang['error_create_password_reset_data'] = 'Não foi possível criar dados de redefinição de senha';

// Forgot Password Email
$lang['email_forgotten_password_subject'] = 'Verificação de Senha E]squecida';
$lang['email_forgot_password_heading'] = 'Redefinir senha para %s';
$lang['email_forgot_password_subheading'] = 'Clique neste link para %s.';
$lang['email_forgot_password_link'] = 'Resetar Sua Senha';

//Reset password
$lang['password_reset_invalid_token'] = 'Não foi possível encontrar o código de redefinição de senha';
$lang['password_reset_expired_token'] = 'Código de redefinição de senha expirado';
$lang['password_reset_failed_update'] = 'Não foi possível atualizar a senha da sua conta';
$lang['password_reset_failed_delete'] = 'Não foi possível excluir os dados de redefinição de senha';

//Login
$lang['login_error_incorrect'] = 'Login ou senha incorretos';
$lang['login_error_timeout'] = 'Temporariamente bloqueado. Tente mais tarde.';
$lang['login_error_role_inactive'] = 'Seu grupo está inativo, você não pode continuar com o login.';
$lang['login_error_account_inactive'] = 'Conta inativa, você não pode continuar com o login.';
$lang['login_error_account_banned'] = 'Conta banida, você não pode continuar com o login.';
$lang['login_error_email_unverified'] = 'Antes de prosseguir, acesse seu e-mail e clique no link de verificação.';

//Roles
$lang['roles_error_unable_create'] = 'Não foi possível criar nova Função';
$lang['roles_error_unable_update'] = 'Não foi possível atualizar a Função';
$lang['roles_error_unable_delete'] = 'Não foi possível apagar a Função';
$lang['roles_error_notallowed_delete'] = 'Não é possível excluir o grupo de Administradores';

//Modules
$lang['modules_error_unable_create'] = 'Não foi possível criar o Novo Módulo';
$lang['modules_error_unable_update'] = 'Não foi possível atualizar o Módulo';
$lang['modules_error_unable_delete'] = 'Não foi possível apagar o Módulo';
