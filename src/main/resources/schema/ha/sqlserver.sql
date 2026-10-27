--
-- Tables of the HA module of the PAM extension, for SQL Server. Created by the
-- module itself on first use, when "pam-ha" turns it on; run this script
-- once instead where its database user may not create tables. Every
-- statement can run again.
--
-- As released in 1.0.0, these statements never change, as databases created
-- by them exist: a later version appends what it changes, as statements that
-- can run again too, as the module runs them all at every start.
--

-- Guacamole servers sharing the database, each as last heard from (UTC),
-- the URL the others reach it at, if set, and, for the status page, its
-- host name, the version of this extension it runs, and when it started
IF OBJECT_ID(N'pam_ha_server', N'U') IS NULL
CREATE TABLE pam_ha_server (

  server_id  nvarchar(36)    NOT NULL,
  last_seen  datetime2(3)    NOT NULL,
  url        nvarchar(1024),
  hostname   nvarchar(256),
  version    nvarchar(64),
  started    datetime2(3),

  PRIMARY KEY (server_id)

);

-- Open sessions of every server, of a connection or through a connection
-- group, or joining one: those of a server no longer heard from are
-- ignored, then removed
IF OBJECT_ID(N'pam_ha_session', N'U') IS NULL
CREATE TABLE pam_ha_session (

  session_id           nvarchar(36)   NOT NULL,
  server_id            nvarchar(36)   NOT NULL,
  tunnel_id            nvarchar(36),
  connection_id        nvarchar(128),
  connection_group_id  nvarchar(128),
  sharing_profile_id   nvarchar(128),
  joined               integer        NOT NULL DEFAULT 0,
  username             nvarchar(128)  NOT NULL,
  remote_host          nvarchar(256),
  started              datetime2(3)   NOT NULL,
  guacd_hostname       nvarchar(256),
  guacd_port           integer,
  guacd_ssl            integer,
  guacd_connection_id  nvarchar(64),
  end_requested        integer        NOT NULL DEFAULT 0,

  PRIMARY KEY (session_id),
  INDEX pam_ha_session_server (server_id),
  INDEX pam_ha_session_tunnel (tunnel_id)

);

-- A single row, locked by a server while it checks the limits of a session
-- and records it, so servers check one at a time
IF OBJECT_ID(N'pam_ha_lock', N'U') IS NULL
CREATE TABLE pam_ha_lock (

  lock_id  integer  NOT NULL,

  PRIMARY KEY (lock_id)

);

IF NOT EXISTS (SELECT 1 FROM pam_ha_lock WHERE lock_id = 1)
INSERT INTO pam_ha_lock (lock_id) VALUES (1);

-- Share links of open sessions, by the SHA-256 of their key
IF OBJECT_ID(N'pam_ha_share', N'U') IS NULL
CREATE TABLE pam_ha_share (

  share_key           nvarchar(64)   NOT NULL,
  session_id          nvarchar(36)   NOT NULL,
  sharing_profile_id  nvarchar(128),
  created             datetime2(3)   NOT NULL,

  PRIMARY KEY (share_key),
  INDEX pam_ha_share_session (session_id)

);

-- Logins, by the SHA-256 of their token: who logged in, as last used on
-- any server (UTC)
IF OBJECT_ID(N'pam_ha_login', N'U') IS NULL
CREATE TABLE pam_ha_login (

  login_id         nvarchar(64)   NOT NULL,
  username         nvarchar(128)  NOT NULL,
  auth_provider    nvarchar(64),
  user_groups      nvarchar(max),
  providers        nvarchar(max),
  share_key        nvarchar(64),
  remote_address   nvarchar(256),
  remote_hostname  nvarchar(256),
  created          datetime2(3)   NOT NULL,
  last_access      datetime2(3)   NOT NULL,

  PRIMARY KEY (login_id),
  INDEX pam_ha_login_last_access (last_access)

);

-- Addresses that failed to log in lately (UTC)
IF OBJECT_ID(N'pam_ha_ban', N'U') IS NULL
CREATE TABLE pam_ha_ban (

  address       nvarchar(128)  NOT NULL,
  failures      integer        NOT NULL,
  last_failure  datetime2(3)   NOT NULL,

  PRIMARY KEY (address)

);

-- TOTP codes used lately, which may not be used again (UTC)
IF OBJECT_ID(N'pam_ha_totp', N'U') IS NULL
CREATE TABLE pam_ha_totp (

  username  nvarchar(128)  NOT NULL,
  code      nvarchar(16)   NOT NULL,
  used      datetime2(3)   NOT NULL,

  PRIMARY KEY (username, code)

);

-- Session recordings, and the server URL each can be fetched from
IF OBJECT_ID(N'pam_ha_recording', N'U') IS NULL
CREATE TABLE pam_ha_recording (

  recording_id  nvarchar(64)    NOT NULL,
  history_uuid  nvarchar(36)    NOT NULL,
  file_name     nvarchar(255)   NOT NULL,
  url           nvarchar(1024)  NOT NULL,
  log_type      nvarchar(40)    NOT NULL,
  file_size     bigint          NOT NULL,

  PRIMARY KEY (recording_id),
  INDEX pam_ha_recording_history (history_uuid)

);
