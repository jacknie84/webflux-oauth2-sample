insert into app_member_client
  (client_id, client_secret, scopes, redirect_uris, access_token_validity_seconds, refresh_token_validity_seconds)
values
  (
    'postman-test-client',
    '{noop}postman-test-secret',
    'openid, email, profile',
    'https://oauth.pstmn.io/v1/callback',
    86400,
    86400
  );
insert into app_member_account (id, username, password) values (1, 'admin', '{noop}1234');
--insert into app_member_account (id, username, password) values (2, '1807608391', '{noop}');
--insert into app_member_social (id, type, account_id) values ('1807608391', 'KAKAO', 2);
