create table if not exists app_member_account(
  id int(11) auto_increment primary key,
  username varchar(255),
  password varchar(255)
);

create table if not exists app_member_social(
  id int(11) auto_increment primary key,
  social_id varchar(255) not null unique,
  type varchar(255) not null,
  account_id int(11) not null,
  foreign key(account_id) references app_member_account(id)
);
