-- WordPress dump (mock fixture for deep content discovery)
CREATE TABLE wp_users (
  ID bigint(20) unsigned NOT NULL,
  user_login varchar(60) NOT NULL,
  user_pass varchar(255) NOT NULL,
  PRIMARY KEY (ID)
);
INSERT INTO wp_users VALUES (1,'admin','$P$Bmockhashvalue');
