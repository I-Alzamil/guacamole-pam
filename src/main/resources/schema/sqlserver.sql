--
-- Tables of the PAM extension, for SQL Server: the same as postgresql.sql,
-- which explains them. Every statement is idempotent, and all are run
-- automatically the first time the extension touches the database, unless
-- the database already has the version recorded at the end.
--
-- Times are stored in UTC (SYSUTCDATETIME).
--
-- Unlike on PostgreSQL and MySQL, no unique index backs the rules on active
-- checkouts and pending requests: the extension enforces them alone, under a
-- lock of the connection's row. Filtered indexes, or indexes of computed
-- columns, would be refused to any statement writing these tables with
-- QUOTED_IDENTIFIER off, such as the trigger with which Guacamole deletes
-- connections when its schema was created by sqlcmd, which would then fail.
--

IF OBJECT_ID(N'pam_schema_version', N'U') IS NULL
CREATE TABLE pam_schema_version (

  version int NOT NULL,

  CONSTRAINT pam_schema_version_pkey PRIMARY KEY (version)

);

IF OBJECT_ID(N'pam_platform', N'U') IS NULL
CREATE TABLE pam_platform (

  platform_id   int            NOT NULL IDENTITY(1,1),
  name          nvarchar(128)  NOT NULL,
  description   nvarchar(1024),
  type          nvarchar(32)   NOT NULL,
  settings      nvarchar(max)  NOT NULL DEFAULT '{}',
  secrets       nvarchar(max)  NOT NULL DEFAULT '{}',
  policy        nvarchar(max)  NOT NULL DEFAULT '{}',
  last_modified datetime2(3)   NOT NULL DEFAULT SYSUTCDATETIME(),

  CONSTRAINT pam_platform_pkey PRIMARY KEY (platform_id),
  CONSTRAINT pam_platform_name UNIQUE (name)

);

IF OBJECT_ID(N'pam_password_policy', N'U') IS NULL
CREATE TABLE pam_password_policy (

  policy_id     int            NOT NULL IDENTITY(1,1),
  name          nvarchar(128)  NOT NULL,
  description   nvarchar(1024),
  rules         nvarchar(max)  NOT NULL DEFAULT '{}',
  last_modified datetime2(3)   NOT NULL DEFAULT SYSUTCDATETIME(),

  CONSTRAINT pam_password_policy_pkey PRIMARY KEY (policy_id),
  CONSTRAINT pam_password_policy_name UNIQUE (name)

);

IF OBJECT_ID(N'pam_rotation_state', N'U') IS NULL
CREATE TABLE pam_rotation_state (

  connection_id    int            NOT NULL,
  last_attempt     datetime2(3),
  last_success     datetime2(3),
  last_status      nvarchar(16),
  last_message     nvarchar(max),
  host_key         nvarchar(256),
  pending_password nvarchar(4000),

  CONSTRAINT pam_rotation_state_pkey PRIMARY KEY (connection_id),
  CONSTRAINT pam_rotation_state_connection
    FOREIGN KEY (connection_id)
    REFERENCES guacamole_connection (connection_id) ON DELETE CASCADE

);

IF OBJECT_ID(N'pam_checkout', N'U') IS NULL
CREATE TABLE pam_checkout (

  checkout_id     int            NOT NULL IDENTITY(1,1),
  connection_id   int,
  connection_name nvarchar(128)  NOT NULL,
  username        nvarchar(128)  NOT NULL,
  remote_host     nvarchar(256),
  reason          nvarchar(500)  NOT NULL,
  checked_out     datetime2(3)   NOT NULL DEFAULT SYSUTCDATETIME(),
  expires         datetime2(3)   NOT NULL,
  released        datetime2(3),
  release_reason  nvarchar(16),
  released_by     nvarchar(128),
  released_host   nvarchar(256),
  reveal_count    int            NOT NULL DEFAULT 1,
  exclusive       bit            NOT NULL DEFAULT 1,
  extensions      int            NOT NULL DEFAULT 0,
  max_extensions  int            NOT NULL DEFAULT 0,

  CONSTRAINT pam_checkout_pkey PRIMARY KEY (checkout_id),
  CONSTRAINT pam_checkout_connection
    FOREIGN KEY (connection_id)
    REFERENCES guacamole_connection (connection_id) ON DELETE SET NULL

);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'pam_checkout_checked_out')
CREATE INDEX pam_checkout_checked_out
  ON pam_checkout (checked_out);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'pam_checkout_released')
CREATE INDEX pam_checkout_released
  ON pam_checkout (released);

-- Active checkouts of a connection, and of its holders
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'pam_checkout_holder')
CREATE INDEX pam_checkout_holder
  ON pam_checkout (connection_id, username, released);

-- Its links to checkouts take no action when the checkout is deleted
-- (checkouts never are): SQL Server refuses a second path of actions from
-- deleting a connection, which also clears the checkout's connection
IF OBJECT_ID(N'pam_request', N'U') IS NULL
CREATE TABLE pam_request (

  request_id         int            NOT NULL IDENTITY(1,1),
  connection_id      int,
  connection_name    nvarchar(128)  NOT NULL,
  username           nvarchar(128)  NOT NULL,
  remote_host        nvarchar(256),
  reason             nvarchar(500)  NOT NULL,
  requested          datetime2(3)   NOT NULL DEFAULT SYSUTCDATETIME(),
  approvals_required int            NOT NULL,
  status             nvarchar(16)   NOT NULL DEFAULT 'PENDING',
  decided            datetime2(3),
  decided_by         nvarchar(128),
  decided_host       nvarchar(256),
  checkout_id        int,
  decision_reason    nvarchar(500),
  starts             datetime2(3),
  ends               datetime2(3),
  periods            int            NOT NULL DEFAULT 1,
  extends_checkout   int,
  extension_minutes  int,

  CONSTRAINT pam_request_pkey PRIMARY KEY (request_id),
  CONSTRAINT pam_request_connection
    FOREIGN KEY (connection_id)
    REFERENCES guacamole_connection (connection_id) ON DELETE SET NULL,
  CONSTRAINT pam_request_checkout
    FOREIGN KEY (checkout_id)
    REFERENCES pam_checkout (checkout_id),
  CONSTRAINT pam_request_extends
    FOREIGN KEY (extends_checkout)
    REFERENCES pam_checkout (checkout_id)

);

-- Pending requests of a connection, and of their requesters
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'pam_request_pending')
CREATE INDEX pam_request_pending
  ON pam_request (connection_id, username, status);

IF OBJECT_ID(N'pam_request_approval', N'U') IS NULL
CREATE TABLE pam_request_approval (

  request_id int            NOT NULL,
  approver   nvarchar(128)  NOT NULL,
  approved   datetime2(3)   NOT NULL DEFAULT SYSUTCDATETIME(),
  remote_host nvarchar(256),

  CONSTRAINT pam_request_approval_pkey PRIMARY KEY (request_id, approver),
  CONSTRAINT pam_request_approval_request
    FOREIGN KEY (request_id)
    REFERENCES pam_request (request_id) ON DELETE CASCADE

);

IF OBJECT_ID(N'pam_user_preference', N'U') IS NULL
CREATE TABLE pam_user_preference (

  username       nvarchar(128)  NOT NULL,
  approval_badge bit            NOT NULL DEFAULT 1,
  rotation_badge bit            NOT NULL DEFAULT 1,

  CONSTRAINT pam_user_preference_pkey PRIMARY KEY (username)

);

IF OBJECT_ID(N'pam_session', N'U') IS NULL
CREATE TABLE pam_session (

  session_id    nvarchar(36)   NOT NULL,
  connection_id int            NOT NULL,
  username      nvarchar(128)  NOT NULL,
  server        nvarchar(128)  NOT NULL,
  started       datetime2(3)   NOT NULL DEFAULT SYSUTCDATETIME(),
  heartbeat     datetime2(3)   NOT NULL DEFAULT SYSUTCDATETIME(),

  CONSTRAINT pam_session_pkey PRIMARY KEY (session_id),
  CONSTRAINT pam_session_connection
    FOREIGN KEY (connection_id)
    REFERENCES guacamole_connection (connection_id) ON DELETE CASCADE

);

IF OBJECT_ID(N'pam_server', N'U') IS NULL
CREATE TABLE pam_server (

  server     nvarchar(128)  NOT NULL,
  heartbeat  datetime2(3)   NOT NULL DEFAULT SYSUTCDATETIME(),

  CONSTRAINT pam_server_pkey PRIMARY KEY (server)

);

IF OBJECT_ID(N'pam_connection_secret', N'U') IS NULL
CREATE TABLE pam_connection_secret (

  connection_id  int            NOT NULL,
  parameter_name nvarchar(128)  NOT NULL,
  value          nvarchar(max)  NOT NULL,

  CONSTRAINT pam_connection_secret_pkey PRIMARY KEY (connection_id, parameter_name),
  CONSTRAINT pam_connection_secret_connection
    FOREIGN KEY (connection_id)
    REFERENCES guacamole_connection (connection_id) ON DELETE CASCADE

);

IF OBJECT_ID(N'pam_setting', N'U') IS NULL
CREATE TABLE pam_setting (

  name          nvarchar(64)    NOT NULL,
  value         nvarchar(1024),
  modified      datetime2(3)    NOT NULL DEFAULT SYSUTCDATETIME(),
  modified_by   nvarchar(128),

  CONSTRAINT pam_setting_pkey PRIMARY KEY (name)

);

-- Last, so the extension can tell the schema is complete
-- (PamDatabase.SCHEMA_VERSION)
IF NOT EXISTS (SELECT 1 FROM pam_schema_version WHERE version = 1)
INSERT INTO pam_schema_version (version) VALUES (1);
