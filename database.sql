-- phpMyAdmin SQL Dump
-- version 5.0.2
-- https://www.phpmyadmin.net/
--
-- Host: laradock_mysql_1
-- Tempo de geração: 25/05/2020 às 20:46
-- Versão do servidor: 5.7.30
-- Versão do PHP: 7.4.5

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Banco de dados: `smarty_smartyacl`
--

-- --------------------------------------------------------

--
-- Estrutura para tabela `acl_login_attempts`
--

CREATE TABLE `acl_login_attempts` (
  `id` int(11) NOT NULL,
  `type` enum('admin','user') COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'admin',
  `login` varchar(191) COLLATE utf8mb4_unicode_ci NOT NULL,
  `ip` varchar(191) COLLATE utf8mb4_unicode_ci NOT NULL,
  `created_at` timestamp NULL DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Estrutura para tabela `acl_modules`
--

CREATE TABLE `acl_modules` (
  `id` int(11) UNSIGNED NOT NULL,
  `name` varchar(191) COLLATE utf8mb4_unicode_ci NOT NULL,
  `controller` varchar(191) COLLATE utf8mb4_unicode_ci NOT NULL,
  `permissions` json NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Despejando dados para a tabela `acl_modules`
--

INSERT INTO `acl_modules` (`id`, `name`, `controller`, `permissions`) VALUES
(1, 'Dashboard', 'admin', '[\"index\", \"edit\", \"delete\", \"create\"]'),
(2, 'Manage Modules', 'modules', '[\"index\", \"edit\", \"delete\", \"create\"]'),
(3, 'Manage Roles', 'roles', '[\"index\", \"edit\", \"delete\", \"create\"]'),
(4, 'Manage Admins', 'admins', '[\"index\", \"edit\", \"delete\", \"create\"]'),
(5, 'Manage Users', 'users', '[\"index\", \"edit\", \"delete\", \"create\"]');

-- --------------------------------------------------------

--
-- Estrutura para tabela `acl_module_permissions`
--

CREATE TABLE `acl_module_permissions` (
  `id` int(11) UNSIGNED NOT NULL,
  `role_id` int(11) UNSIGNED NOT NULL,
  `module_id` int(11) UNSIGNED NOT NULL,
  `permission` varchar(191) COLLATE utf8mb4_unicode_ci NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Despejando dados para a tabela `acl_module_permissions`
--

INSERT INTO `acl_module_permissions` (`id`, `role_id`, `module_id`, `permission`) VALUES
(1, 1, 1, 'edit'),
(2, 1, 1, 'delete'),
(3, 1, 2, 'edit'),
(4, 1, 3, 'edit'),
(5, 1, 3, 'delete'),
(6, 1, 1, 'create'),
(7, 1, 2, 'delete'),
(8, 1, 3, 'create'),
(9, 1, 1, 'index'),
(10, 1, 2, 'index'),
(11, 1, 3, 'index'),
(12, 2, 1, 'index'),
(13, 3, 1, 'index'),
(14, 3, 2, 'index'),
(15, 3, 3, 'index'),
(16, 1, 2, 'create'),
(17, 1, 4, 'index'),
(18, 1, 4, 'edit'),
(19, 1, 4, 'delete'),
(20, 1, 4, 'create'),
(21, 1, 5, 'index'),
(22, 1, 5, 'edit'),
(23, 1, 5, 'delete'),
(24, 1, 5, 'create'),
(25, 2, 5, 'edit'),
(26, 2, 5, 'delete'),
(27, 2, 5, 'create'),
(28, 3, 4, 'index'),
(29, 2, 5, 'index'),
(30, 2, 3, 'index'),
(31, 2, 4, 'index'),
(32, 2, 4, 'delete'),
(33, 3, 5, 'index'),
(34, 3, 1, 'edit');

-- --------------------------------------------------------

--
-- Estrutura para tabela `acl_password_resets`
--

CREATE TABLE `acl_password_resets` (
  `type` enum('admin','user') COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'admin',
  `email` varchar(191) COLLATE utf8mb4_unicode_ci NOT NULL,
  `token` varchar(191) COLLATE utf8mb4_unicode_ci NOT NULL,
  `token_code` varchar(191) COLLATE utf8mb4_unicode_ci NOT NULL,
  `created_at` timestamp NULL DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Estrutura para tabela `acl_roles`
--

CREATE TABLE `acl_roles` (
  `id` int(11) UNSIGNED NOT NULL,
  `name` varchar(191) COLLATE utf8mb4_unicode_ci NOT NULL,
  `status` enum('active','inactive') COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'active'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Despejando dados para a tabela `acl_roles`
--

INSERT INTO `acl_roles` (`id`, `name`, `status`) VALUES
(1, 'Super Admin', 'active'),
(2, 'Admin', 'inactive'),
(3, 'Demo', 'active');

-- --------------------------------------------------------

--
-- Estrutura para tabela `admins`
--

CREATE TABLE `admins` (
  `id` int(11) UNSIGNED NOT NULL,
  `username` varchar(191) COLLATE utf8mb4_unicode_ci NOT NULL,
  `password` varchar(191) COLLATE utf8mb4_unicode_ci NOT NULL,
  `name` varchar(191) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `email` varchar(191) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `role_id` int(11) NOT NULL,
  `status` enum('inactive','active','banned') COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'active',
  `last_login` timestamp NULL DEFAULT NULL,
  `ip` varchar(191) COLLATE utf8mb4_unicode_ci NOT NULL,
  `email_verified_at` timestamp NULL DEFAULT NULL,
  `email_activator` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `email_activator_code` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `remember_token` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `remember_token_code` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `updated_at` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Despejando dados para a tabela `admins`
--

INSERT INTO `admins` (`id`, `username`, `password`, `name`, `email`, `role_id`, `status`, `last_login`, `ip`, `email_verified_at`, `email_activator`, `email_activator_code`, `remember_token`, `remember_token_code`, `created_at`, `updated_at`) VALUES
(1, 'admin', '$2y$10$TmJKG3yV8o7kCycAdQI0/.7jJ5uhO3RC9pyJOMlbFHmbEzUk8JMfu', 'Name Last Name', 'admin@admin.com', 1, 'active', '2020-05-25 20:05:36', '172.19.0.1', '2020-05-21 17:19:04', NULL, NULL, NULL, NULL, '2020-05-17 19:30:21', '2020-05-25 20:05:36');

-- --------------------------------------------------------

--
-- Estrutura para tabela `users`
--

CREATE TABLE `users` (
  `id` int(11) UNSIGNED NOT NULL,
  `username` varchar(191) COLLATE utf8mb4_unicode_ci NOT NULL,
  `password` varchar(191) COLLATE utf8mb4_unicode_ci NOT NULL,
  `name` varchar(191) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `email` varchar(191) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `status` enum('inactive','active','banned') COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'active',
  `last_login` timestamp NULL DEFAULT NULL,
  `ip` varchar(191) COLLATE utf8mb4_unicode_ci NOT NULL,
  `email_verified_at` timestamp NULL DEFAULT NULL,
  `email_activator` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `email_activator_code` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `remember_token` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `remember_token_code` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `updated_at` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Índices de tabelas apagadas
--

--
-- Índices de tabela `acl_login_attempts`
--
ALTER TABLE `acl_login_attempts`
  ADD PRIMARY KEY (`id`);

--
-- Índices de tabela `acl_modules`
--
ALTER TABLE `acl_modules`
  ADD PRIMARY KEY (`id`);

--
-- Índices de tabela `acl_module_permissions`
--
ALTER TABLE `acl_module_permissions`
  ADD PRIMARY KEY (`id`),
  ADD KEY `module_id` (`module_id`),
  ADD KEY `role_id` (`role_id`);

--
-- Índices de tabela `acl_password_resets`
--
ALTER TABLE `acl_password_resets`
  ADD KEY `password_resets_email_index` (`email`);

--
-- Índices de tabela `acl_roles`
--
ALTER TABLE `acl_roles`
  ADD PRIMARY KEY (`id`);

--
-- Índices de tabela `admins`
--
ALTER TABLE `admins`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `username` (`username`),
  ADD UNIQUE KEY `email` (`email`),
  ADD UNIQUE KEY `email_activator` (`email_activator`),
  ADD UNIQUE KEY `remember_token` (`remember_token`);

--
-- Índices de tabela `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `username` (`username`),
  ADD UNIQUE KEY `email` (`email`),
  ADD UNIQUE KEY `email_activator` (`email_activator`),
  ADD UNIQUE KEY `remember_token` (`remember_token`);

--
-- AUTO_INCREMENT de tabelas apagadas
--

--
-- AUTO_INCREMENT de tabela `acl_login_attempts`
--
ALTER TABLE `acl_login_attempts`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT de tabela `acl_modules`
--
ALTER TABLE `acl_modules`
  MODIFY `id` int(11) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=6;

--
-- AUTO_INCREMENT de tabela `acl_module_permissions`
--
ALTER TABLE `acl_module_permissions`
  MODIFY `id` int(11) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=35;

--
-- AUTO_INCREMENT de tabela `acl_roles`
--
ALTER TABLE `acl_roles`
  MODIFY `id` int(11) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=4;

--
-- AUTO_INCREMENT de tabela `admins`
--
ALTER TABLE `admins`
  MODIFY `id` int(11) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=48;

--
-- AUTO_INCREMENT de tabela `users`
--
ALTER TABLE `users`
  MODIFY `id` int(11) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- Restrições para dumps de tabelas
--

--
-- Restrições para tabelas `acl_module_permissions`
--
ALTER TABLE `acl_module_permissions`
  ADD CONSTRAINT `acl_module_permissions_ibfk_1` FOREIGN KEY (`module_id`) REFERENCES `acl_modules` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `acl_module_permissions_ibfk_2` FOREIGN KEY (`role_id`) REFERENCES `acl_roles` (`id`) ON DELETE CASCADE;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
