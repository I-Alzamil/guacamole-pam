# Installation

## Requirements

- Guacamole 1.6 with one of its **database authentications** installed and
  working: PostgreSQL (`guacamole-auth-jdbc-postgresql`), MySQL or MariaDB
  (`guacamole-auth-jdbc-mysql`), or SQL Server (`guacamole-auth-jdbc-sqlserver`).
  The extension manages the connections stored there, and reuses its settings
  (`postgresql-*`, `mysql-*` or `sqlserver-*`, SSL settings included) and its
  JDBC driver. Nothing else needs configuring.
- Java 11 or later, as for Guacamole.

Supported databases: PostgreSQL 13 or later, MySQL 8.0 or later, MariaDB 10.6
or later, and SQL Server 2017 or later, with Microsoft's driver (the default
`sqlserver-driver`, `microsoft2005`). The extension connects as Guacamole's
own authentication does, with the same SSL mode, certificates and driver:
MySQL's `mysql-driver` choosing between the MySQL and MariaDB drivers is
followed too.

Two problems of Guacamole 1.6.0 itself, not of this extension, affect
these databases:

- **SQL Server**: Guacamole's SQL Server authentication doesn't start, as two
  of its MyBatis mappers aren't valid XML (`UserGroupPermissionMapper.xml`
  has `<test>` where `<otherwise>` belongs, and `ConnectionRecordMapper.xml`
  `<hen` for `<when`). It needs those two lines fixed in its jar
  (`lab/database.sh` shows how) until a Guacamole release fixes them.
- **MySQL and MariaDB**: Guacamole can't delete user groups (its statement
  lacks an `AND`), nor add a group to another (its statement calls a
  misspelled method).

If several database authentications are configured, set which one's
connections the extension manages in `guacamole.properties` (or
`PAM_DATABASE` in the Docker image):

```
pam-database: mysql
```

Without a database authentication (for example with only LDAP or
`user-mapping.xml`), the extension stays inactive. It logs one warning saying
why, and Guacamole works exactly as without it.

The extension has its own version (`1.0.0`, following semantic versioning),
and each build is made for one Guacamole release, 1.6.0 for now: Guacamole
skips extensions built for another release. To build for another release, set
`guacamole.version` in `pom.xml`. [CHANGELOG.md](../CHANGELOG.md) lists what each
release changes.

## Installing the extension

1. Build the extension with `mvn package`, or use a released jar, then copy
   `guacamole-pam-<version>.jar` into `GUACAMOLE_HOME/extensions/`.
2. Restart Guacamole.

The first time the extension uses the database, it creates its tables (all
named `pam_*`, from `schema/postgresql.sql`, `schema/mysql.sql` or
`schema/sqlserver.sql` in the jar) and adds three default SSH platforms,
"Unix", "macOS" and "Windows". Later starts find the tables and leave them
alone. On MySQL and SQL Server, the extension stores its times in UTC.

Times of checkouts and requests follow the database's clock, whatever the
clocks of Guacamole's server or of the browsers say: a checkout counts down
in the browser by the server's time. The log warns when the database's clock
is more than 5 seconds from Guacamole's server's; keep both synchronized
(NTP) all the same, as Guacamole's own times follow its server's.

### If Guacamole's database user may not create tables

Guacamole's installation guide grants its database user only
`SELECT, INSERT, UPDATE, DELETE` on the tables (on SQL Server, the roles
`db_datareader` and `db_datawriter`), and such a user can't create the
extension's tables. The log then explains this once, naming the user and what
to run. Until the tables exist, connections stored in the database can't be
opened, because their access can't be checked.

To fix it, create the tables once as the database owner. No restart is needed.

- **PostgreSQL**: create them, then grant them to Guacamole's user, as for
  Guacamole's own tables:

  ```sh
  unzip -p guacamole-pam-<version>.jar schema/postgresql.sql | psql -U <owner> -d <guacamole database>
  ```

  ```sql
  GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA public TO guacamole_user;
  GRANT SELECT,USAGE ON ALL SEQUENCES IN SCHEMA public TO guacamole_user;
  ```
- **MySQL or MariaDB**: the grants of Guacamole's guide cover the whole
  database, so new tables need none:

  ```sh
  unzip -p guacamole-pam-<version>.jar schema/mysql.sql | mysql -u <owner> -p <guacamole database>
  ```
- **SQL Server**: the roles of Guacamole's guide cover new tables too:

  ```sh
  unzip -p guacamole-pam-<version>.jar schema/sqlserver.sql > pam.sql
  sqlcmd -S <server> -U <owner> -d <guacamole database> -i pam.sql
  ```

Tables created this way start without the three default platforms: add them
with **Restore defaults** on the **Platforms** tab.

Do the same after upgrading to a version that changes the tables: until then,
connections stored in the database can't be opened, as above.
