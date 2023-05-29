Insert Into _roles(id, name, description, priority) values (1, 'ADMIN', 'Admin User',3);
Insert Into _roles(id, name, description, priority) values (2, 'MODERATOR', 'Moderator User',2);
Insert Into _roles(id, name, description, priority) values (3, 'USER', 'Basic User',1);

Insert Into _permissions (id, name, description) VALUES (1, 'update_all_users', 'Allows the user to update all users');
Insert Into _permissions (id, name, description) VALUES (2, 'create_all_users', 'Allows the user to create another users with any type of role');
Insert Into _permissions (id, name, description) VALUES (3, 'read_all_users', 'Allows the user to read all the others users data');
Insert Into _permissions (id, name, description) VALUES (4, 'disable_all_users', 'Allows the user to disable all users');
Insert Into _permissions (id, name, description) VALUES (5, 'delete_all_users', 'Allows the user to delete all the others users data and account');
Insert Into _permissions (id, name, description) VALUES (6, 'create_roles', 'Allows the user to create roles');
Insert Into _permissions (id, name, description) VALUES (7, 'read_role', 'Allows the user to read roles');
Insert Into _permissions (id, name, description) VALUES (8, 'update_roles', 'Allows the user to update roles');
Insert Into _permissions (id, name, description) VALUES (9, 'delete_roles', 'Allows the user to update roles');
Insert Into _permissions (id, name, description) VALUES (10, 'admin_roles', 'Allows the user all actions over the roles');
Insert Into _permissions (id, name, description) VALUES (11, 'create_permissions', 'Allows the user to create permissions');
Insert Into _permissions (id, name, description) VALUES (12, 'read_permissions', 'Allows the user to create permissions');
Insert Into _permissions (id, name, description) VALUES (13, 'update_permissions', 'Allows the user to create permissions');
Insert Into _permissions (id, name, description) VALUES (14, 'delete_permissions', 'Allows the user to create permissions');
Insert Into _permissions (id, name, description) VALUES (15, 'admin_permissions', 'Allows the user all actions over the permissions');
Insert Into _permissions (id, name, description) VALUES (16, 'user_permissions', 'Allows the user all basic over permissions');
Insert Into _permissions (id, name, description) VALUES (17, 'update_user', 'Allows the user to update it own profile.');
Insert Into _permissions (id, name, description) VALUES (18, 'delete_users', 'Allows the user to delete users.');
Insert Into _permissions (id, name, description) VALUES (19, 'refresh_token', 'Allows the user refresh token.');


Insert Into roles_permissions (role_id, permission_id) VALUES (1, 1);
Insert Into roles_permissions (role_id, permission_id) VALUES (1, 2);
Insert Into roles_permissions (role_id, permission_id) VALUES (1, 3);
Insert Into roles_permissions (role_id, permission_id) VALUES (1, 4);
Insert Into roles_permissions (role_id, permission_id) VALUES (1, 13);
Insert Into roles_permissions (role_id, permission_id) VALUES (1, 19);
Insert Into roles_permissions (role_id, permission_id) VALUES (2, 1);
Insert Into roles_permissions (role_id, permission_id) VALUES (2, 2);
Insert Into roles_permissions (role_id, permission_id) VALUES (2, 3);
Insert Into roles_permissions (role_id, permission_id) VALUES (2, 4);
Insert Into roles_permissions (role_id, permission_id) VALUES (2, 18);
Insert Into roles_permissions (role_id, permission_id) VALUES (2, 19);
Insert Into roles_permissions (role_id, permission_id) VALUES (3, 16);
Insert Into roles_permissions (role_id, permission_id) VALUES (3, 17);
Insert Into roles_permissions (role_id, permission_id) VALUES (3, 19);


insert into _user(email, firstname, lastname, password, date_joined, last_login, is_active, role, id) values ('user@gmail.com', 'User', 'Resu', '$2a$10$UiYNO2nXyyQ0Awxb2CCzMeI9BaMEKQ2gq2GkjO3FkR8QeSo6KJEFK', '2023-01-16 10:38:01.383', '2023-01-16 10:38:01.383', true, 3, 1);
insert into _user(email, firstname, lastname, password, date_joined, last_login, is_active, role, id) values ('mod@gmail.com', 'Mod', 'Dom', '$2a$10$UiYNO2nXyyQ0Awxb2CCzMeI9BaMEKQ2gq2GkjO3FkR8QeSo6KJEFK', '2023-01-16 10:38:01.383', '2023-01-16 10:38:01.383', true, 2, 2);
insert into _user(email, firstname, lastname, password, date_joined, last_login, is_active, role, id) values ('admin@gmail.com', 'Admin', 'Nimda', '$2a$10$UiYNO2nXyyQ0Awxb2CCzMeI9BaMEKQ2gq2GkjO3FkR8QeSo6KJEFK', '2023-01-16 10:38:01.383', '2023-01-16 10:38:01.383', true, 1, 3);