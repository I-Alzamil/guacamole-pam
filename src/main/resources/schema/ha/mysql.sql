--
-- Tables of the HA module of the PAM extension, for MySQL and MariaDB.
-- Created by the module itself on first use, when "pam-ha" turns it on; run
-- this script once instead where its database user may not create tables.
-- Every statement can run again.
--

-- Guacamole servers sharing the database, each as last heard from (UTC),
-- the URL the others reach it at, if set, and, for the status page, its
-- host name, the version of this extension it runs, and when it started
CREATE TABLE IF NOT EXISTS pam_ha_server (

  server_id  varchar(36)    NOT NULL,
  last_seen  datetime(3)    NOT NULL,
  url        varchar(1024),
  hostname   varchar(256),
  version    varchar(64),
  started    datetime(3),

  PRIMARY KEY (server_id)

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Open sessions of every server, of a connection or through a connection
-- group, or joining one: those of a server no longer heard from are
-- ignored, then removed
CREATE TABLE IF NOT EXISTS pam_ha_session (

  session_id           varchar(36)   NOT NULL,
  server_id            varchar(36)   NOT NULL,
  tunnel_id            varchar(36),
  connection_id        varchar(128),
  connection_group_id  varchar(128),
  sharing_profile_id   varchar(128),
  joined               integer       NOT NULL DEFAULT 0,
  username             varchar(128)  NOT NULL,
  remote_host          varchar(256),
  started              datetime(3)   NOT NULL,
  guacd_hostname       varchar(256),
  guacd_port           integer,
  guacd_ssl            integer,
  guacd_connection_id  varchar(64),
  end_requested        integer       NOT NULL DEFAULT 0,

  PRIMARY KEY (session_id),
  KEY pam_ha_session_server (server_id),
  KEY pam_ha_session_tunnel (tunnel_id)

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- A single row, locked by a server while it checks the limits of a session
-- and records it, so servers check one at a time
CREATE TABLE IF NOT EXISTS pam_ha_lock (

  lock_id  integer  NOT NULL,

  PRIMARY KEY (lock_id)

) ENGINE=InnoDB;

INSERT IGNORE INTO pam_ha_lock (lock_id) VALUES (1);

-- Share links of open sessions, by the SHA-256 of their key
CREATE TABLE IF NOT EXISTS pam_ha_share (

  share_key           varchar(64)   NOT NULL,
  session_id          varchar(36)   NOT NULL,
  sharing_profile_id  varchar(128),
  created             datetime(3)   NOT NULL,

  PRIMARY KEY (share_key),
  KEY pam_ha_share_session (session_id)

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Logins, by the SHA-256 of their token: who logged in, as last used on
-- any server (UTC)
CREATE TABLE IF NOT EXISTS pam_ha_login (

  login_id         varchar(64)   NOT NULL,
  username         varchar(128)  NOT NULL,
  user_groups      text,
  providers        text,
  share_key        varchar(64),
  remote_address   varchar(256),
  remote_hostname  varchar(256),
  created          datetime(3)   NOT NULL,
  last_access      datetime(3)   NOT NULL,

  PRIMARY KEY (login_id),
  KEY pam_ha_login_last_access (last_access)

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Addresses that failed to log in lately (UTC)
CREATE TABLE IF NOT EXISTS pam_ha_ban (

  address       varchar(128)  NOT NULL,
  failures      integer       NOT NULL,
  last_failure  datetime(3)   NOT NULL,

  PRIMARY KEY (address)

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- TOTP codes used lately, which may not be used again (UTC)
CREATE TABLE IF NOT EXISTS pam_ha_totp (

  username  varchar(128)  NOT NULL,
  code      varchar(16)   NOT NULL,
  used      datetime(3)   NOT NULL,

  PRIMARY KEY (username, code)

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Session recordings, and the server URL each can be fetched from
CREATE TABLE IF NOT EXISTS pam_ha_recording (

  recording_id  varchar(64)    NOT NULL,
  history_uuid  varchar(36)    NOT NULL,
  file_name     varchar(255)   NOT NULL,
  url           varchar(1024)  NOT NULL,
  log_type      varchar(40)    NOT NULL,
  file_size     bigint         NOT NULL,

  PRIMARY KEY (recording_id),
  KEY pam_ha_recording_history (history_uuid)

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
