insert into t_user(id, c_username, c_password)
values (1, 'j.jameson', '{noop}password');

insert into t_user_authority(id_user, c_authority)
values (1, 'ROLE_MANAGER');