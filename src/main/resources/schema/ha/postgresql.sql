--
-- Tables of the HA module of the PAM extension, for PostgreSQL. Created by the
-- module itself on first use, when "pam-ha" turns it on; run this script
-- once instead where its database user may not create tables. Every
-- statement can run again.
--
-- As released in 1.0.0, these statements never change, as databases created
-- by them exist: a later version appends what it changes, as statements that
-- can run again too, as the module runs them all at every start.
--

-- Guacamole servers sharing the database, each as last heard from, the URL
-- the others reach it at, if set, and, for the status page, its host name,
-- the version of this extension it runs, and when it started
CREATE TABLE IF NOT EXISTS pam_ha_server (

  server_id  varchar(36)    NOT NULL,
  last_seen  timestamptz    NOT NULL,
  url        varchar(1024),
  hostname   varchar(256),
  version    varchar(64),
  started    timestamptz,

  PRIMARY KEY (server_id)

);

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
  started              timestamptz   NOT NULL DEFAULT CURRENT_TIMESTAMP,
  guacd_hostname       varchar(256),
  guacd_port           integer,
  guacd_ssl            integer,
  guacd_connection_id  varchar(64),
  end_requested        integer       NOT NULL DEFAULT 0,

  PRIMARY KEY (session_id)

);

CREATE INDEX IF NOT EXISTS pam_ha_session_server
  ON pam_ha_session (server_id);

CREATE INDEX IF NOT EXISTS pam_ha_session_tunnel
  ON pam_ha_session (tunnel_id);

-- A single row, locked by a server while it checks the limits of a session
-- and records it, so servers check one at a time
CREATE TABLE IF NOT EXISTS pam_ha_lock (

  lock_id  integer  NOT NULL,

  PRIMARY KEY (lock_id)

);

INSERT INTO pam_ha_lock (lock_id) VALUES (1) ON CONFLICT DO NOTHING;

-- Share links of open sessions, by the SHA-256 of their key
CREATE TABLE IF NOT EXISTS pam_ha_share (

  share_key           varchar(64)   NOT NULL,
  session_id          varchar(36)   NOT NULL,
  sharing_profile_id  varchar(128),
  created             timestamptz   NOT NULL,

  PRIMARY KEY (share_key)

);

CREATE INDEX IF NOT EXISTS pam_ha_share_session
  ON pam_ha_share (session_id);

-- Logins, by the SHA-256 of their token: who logged in, as last used on
-- any server
CREATE TABLE IF NOT EXISTS pam_ha_login (

  login_id         varchar(64)   NOT NULL,
  username         varchar(128)  NOT NULL,
  auth_provider    varchar(64),
  user_groups      text,
  providers        text,
  share_key        varchar(64),
  remote_address   varchar(256),
  remote_hostname  varchar(256),
  created          timestamptz   NOT NULL,
  last_access      timestamptz   NOT NULL,

  PRIMARY KEY (login_id)

);

CREATE INDEX IF NOT EXISTS pam_ha_login_last_access
  ON pam_ha_login (last_access);

-- Addresses that failed to log in lately
CREATE TABLE IF NOT EXISTS pam_ha_ban (

  address       varchar(128)  NOT NULL,
  failures      integer       NOT NULL,
  last_failure  timestamptz   NOT NULL,

  PRIMARY KEY (address)

);

-- TOTP codes used lately, which may not be used again
CREATE TABLE IF NOT EXISTS pam_ha_totp (

  username  varchar(128)  NOT NULL,
  code      varchar(16)   NOT NULL,
  used      timestamptz   NOT NULL,

  PRIMARY KEY (username, code)

);

-- Session recordings, and the server URL each can be fetched from
CREATE TABLE IF NOT EXISTS pam_ha_recording (

  recording_id  varchar(64)    NOT NULL,
  history_uuid  varchar(36)    NOT NULL,
  file_name     varchar(255)   NOT NULL,
  url           varchar(1024)  NOT NULL,
  log_type      varchar(40)    NOT NULL,
  file_size     bigint         NOT NULL,

  PRIMARY KEY (recording_id)

);

CREATE INDEX IF NOT EXISTS pam_ha_recording_history
  ON pam_ha_recording (history_uuid);
