--
-- Tables of the PAM extension, for MySQL and MariaDB: the same as
-- postgresql.sql, which explains them. Every statement is idempotent, and
-- all are run automatically the first time the extension touches the
-- database, unless the database already has the version recorded at the end.
--
-- Times are stored in UTC: the extension's sessions use UTC as their time
-- zone. Unique indexes ignore rows whose indexed values are all NULL, so
-- generated columns, NULL but for the rows a rule applies to, enforce the
-- rules PostgreSQL enforces with partial indexes.
--

CREATE TABLE IF NOT EXISTS pam_schema_version (

  version integer NOT NULL,

  PRIMARY KEY (version)

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS pam_platform (

  platform_id   integer       NOT NULL AUTO_INCREMENT,
  name          varchar(128)  NOT NULL,
  description   varchar(1024),
  type          varchar(32)   NOT NULL,
  settings      mediumtext    NOT NULL,
  secrets       mediumtext    NOT NULL,
  policy        mediumtext    NOT NULL,
  last_modified datetime(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

  PRIMARY KEY (platform_id),
  UNIQUE KEY pam_platform_name (name)

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS pam_password_policy (

  policy_id     integer       NOT NULL AUTO_INCREMENT,
  name          varchar(128)  NOT NULL,
  description   varchar(1024),
  rules         mediumtext    NOT NULL,
  last_modified datetime(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

  PRIMARY KEY (policy_id),
  UNIQUE KEY pam_password_policy_name (name)

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS pam_rotation_state (

  connection_id    integer       NOT NULL,
  last_attempt     datetime(3),
  last_success     datetime(3),
  last_status      varchar(16),
  last_message     text,
  host_key         varchar(256),
  pending_password varchar(4096),

  PRIMARY KEY (connection_id),
  CONSTRAINT pam_rotation_state_connection
    FOREIGN KEY (connection_id)
    REFERENCES guacamole_connection (connection_id) ON DELETE CASCADE

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS pam_checkout (

  checkout_id     integer       NOT NULL AUTO_INCREMENT,
  connection_id   integer,
  connection_name varchar(128)  NOT NULL,
  username        varchar(128)  NOT NULL,
  remote_host     varchar(256),
  reason          varchar(500)  NOT NULL,
  checked_out     datetime(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  expires         datetime(3)   NOT NULL,
  released        datetime(3),
  release_reason  varchar(16),
  released_by     varchar(128),
  released_host   varchar(256),
  reveal_count    integer       NOT NULL DEFAULT 1,
  exclusive       boolean       NOT NULL DEFAULT TRUE,
  extensions      integer       NOT NULL DEFAULT 0,
  max_extensions  integer       NOT NULL DEFAULT 0,

  -- The connection of an active exclusive checkout, and of any active one
  active_exclusive integer AS (CASE WHEN released IS NULL AND exclusive THEN connection_id END) VIRTUAL,
  active_holder    integer AS (CASE WHEN released IS NULL THEN connection_id END) VIRTUAL,

  PRIMARY KEY (checkout_id),
  KEY pam_checkout_checked_out (checked_out),
  KEY pam_checkout_released (released),

  -- One exclusive holder per connection, and one active checkout per user
  UNIQUE KEY pam_checkout_exclusive (active_exclusive),
  UNIQUE KEY pam_checkout_holder (active_holder, username),

  CONSTRAINT pam_checkout_connection
    FOREIGN KEY (connection_id)
    REFERENCES guacamole_connection (connection_id) ON DELETE SET NULL

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS pam_request (

  request_id         integer       NOT NULL AUTO_INCREMENT,
  connection_id      integer,
  connection_name    varchar(128)  NOT NULL,
  username           varchar(128)  NOT NULL,
  remote_host        varchar(256),
  reason             varchar(500)  NOT NULL,
  requested          datetime(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  approvals_required integer       NOT NULL,
  status             varchar(16)   NOT NULL DEFAULT 'PENDING',
  decided            datetime(3),
  decided_by         varchar(128),
  decided_host       varchar(256),
  checkout_id        integer,
  decision_reason    varchar(500),
  starts             datetime(3),
  ends               datetime(3),
  periods            integer       NOT NULL DEFAULT 1,
  extends_checkout   integer,
  extension_minutes  integer,

  -- The connection of a pending request, besides extensions
  pending_connection integer AS (CASE WHEN status = 'PENDING' AND extends_checkout IS NULL
                                 THEN connection_id END) VIRTUAL,

  PRIMARY KEY (request_id),

  -- At most one pending request per user and connection, besides extensions
  UNIQUE KEY pam_request_pending (pending_connection, username),

  CONSTRAINT pam_request_connection
    FOREIGN KEY (connection_id)
    REFERENCES guacamole_connection (connection_id) ON DELETE SET NULL,
  CONSTRAINT pam_request_checkout
    FOREIGN KEY (checkout_id)
    REFERENCES pam_checkout (checkout_id) ON DELETE SET NULL,
  CONSTRAINT pam_request_extends
    FOREIGN KEY (extends_checkout)
    REFERENCES pam_checkout (checkout_id) ON DELETE SET NULL

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS pam_request_approval (

  request_id integer       NOT NULL,
  approver   varchar(128)  NOT NULL,
  approved   datetime(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  remote_host varchar(256),

  PRIMARY KEY (request_id, approver),
  CONSTRAINT pam_request_approval_request
    FOREIGN KEY (request_id)
    REFERENCES pam_request (request_id) ON DELETE CASCADE

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS pam_user_preference (

  username       varchar(128)  NOT NULL,
  approval_badge boolean       NOT NULL DEFAULT TRUE,
  rotation_badge boolean       NOT NULL DEFAULT TRUE,
  admin_email    boolean       NOT NULL DEFAULT TRUE,
  approval_email boolean       NOT NULL DEFAULT TRUE,
  own_email      boolean       NOT NULL DEFAULT TRUE,
  email_language varchar(16),

  PRIMARY KEY (username)

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- The groups each user belonged to at their last login, as every
-- extension gave them, such as LDAP: emails to the members of a group reach
-- those Guacamole's own tables do not list
CREATE TABLE IF NOT EXISTS pam_login_group (

  username    varchar(128)  NOT NULL,
  group_name  varchar(128)  NOT NULL,

  PRIMARY KEY (username, group_name)

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS pam_session (

  session_id    varchar(36)   NOT NULL,
  connection_id integer       NOT NULL,
  username      varchar(128)  NOT NULL,
  server        varchar(128)  NOT NULL,
  started       datetime(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  heartbeat     datetime(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

  PRIMARY KEY (session_id),
  CONSTRAINT pam_session_connection
    FOREIGN KEY (connection_id)
    REFERENCES guacamole_connection (connection_id) ON DELETE CASCADE

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS pam_connection_secret (

  connection_id  integer       NOT NULL,
  parameter_name varchar(128)  NOT NULL,
  value          mediumtext    NOT NULL,

  PRIMARY KEY (connection_id, parameter_name),
  CONSTRAINT pam_connection_secret_connection
    FOREIGN KEY (connection_id)
    REFERENCES guacamole_connection (connection_id) ON DELETE CASCADE

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS pam_setting (

  name          varchar(64)   NOT NULL,
  value         varchar(8000),
  modified      datetime(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  modified_by   varchar(128),

  PRIMARY KEY (name)

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS pam_email_language (

  code          varchar(16)   NOT NULL,
  name          varchar(64)   NOT NULL,
  content       mediumtext    NOT NULL,
  modified      datetime(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  modified_by   varchar(128),

  PRIMARY KEY (code)

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Last, so the extension can tell the schema is complete
-- (PamDatabase.SCHEMA_VERSION)
INSERT IGNORE INTO pam_schema_version (version) VALUES (1);
