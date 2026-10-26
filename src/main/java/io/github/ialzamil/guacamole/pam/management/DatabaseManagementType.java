package io.github.ialzamil.guacamole.pam.management;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.apache.guacamole.GuacamoleClientException;
import org.apache.guacamole.form.EnumField;
import org.apache.guacamole.form.Field;
import org.apache.guacamole.form.Form;
import org.apache.guacamole.form.MultilineField;
import org.apache.guacamole.form.NumericField;
import org.apache.guacamole.form.PasswordField;
import org.apache.guacamole.form.TextField;

import io.github.ialzamil.guacamole.pam.database.DatabaseClient;
import io.github.ialzamil.guacamole.pam.database.DatabaseTarget.Kind;
import io.github.ialzamil.guacamole.pam.database.DatabaseTarget;
import io.github.ialzamil.guacamole.pam.db.ConnectionRepository.Target;
import io.github.ialzamil.guacamole.pam.platform.Platform;

/**
 * Changes passwords of database accounts: PostgreSQL roles, MySQL and
 * MariaDB accounts, and SQL Server logins, over the driver of each database
 * installed with Guacamole. The server, its encryption and the optional
 * administrator account belong to the platform; each connection's account
 * is its username (with, on MySQL and MariaDB, the host part of the
 * account). Accounts are Account connections: Guacamole opens no sessions
 * to databases, so their holders use the password in their own client.
 */
public class DatabaseManagementType implements ManagementType {

    public static final String NAME = "database";

    // Platform settings, named as DatabaseTarget reads them
    public static final String TYPE = DatabaseTarget.TYPE;
    public static final String HOSTNAME = DatabaseTarget.HOSTNAME;
    public static final String PORT = DatabaseTarget.PORT;
    public static final String DATABASE = DatabaseTarget.DATABASE;
    public static final String ENCRYPTION = DatabaseTarget.ENCRYPTION;
    public static final String CA_CERTIFICATES = DatabaseTarget.CA_CERTIFICATES;
    public static final String ADMIN_USERNAME = DatabaseTarget.ADMIN_USERNAME;
    public static final String ADMIN_PASSWORD = DatabaseTarget.ADMIN_PASSWORD;

    /**
     * Where the administrator password, and passwords, are sent, and how
     * safely.
     */
    private static final Set<String> DESTINATION_FIELDS = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
            TYPE, HOSTNAME, PORT, DATABASE, ENCRYPTION, CA_CERTIFICATES)));

    /**
     * Connection attribute: host part of a MySQL or MariaDB account, "%" if
     * empty.
     */
    public static final String ACCOUNT_HOST = "pam-database-account-host";

    private final DatabaseClient database = new DatabaseClient();

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public Collection<Form> getPlatformForms() {
        return Arrays.asList(
            new Form("database-server", Arrays.<Field>asList(
                new EnumField(TYPE, Arrays.asList(Kind.POSTGRESQL.getValue(), Kind.MYSQL.getValue(),
                        Kind.SQLSERVER.getValue())),
                new TextField(HOSTNAME),
                new NumericField(PORT),
                new TextField(DATABASE)
            )),
            new Form("database-trust", Arrays.<Field>asList(
                new EnumField(ENCRYPTION, Arrays.asList("", DatabaseTarget.ENCRYPTION_UNVERIFIED,
                        DatabaseTarget.ENCRYPTION_NONE)),
                new MultilineField(CA_CERTIFICATES)
            )),
            new Form("database-rotation", Arrays.<Field>asList(
                new TextField(ADMIN_USERNAME),
                new PasswordField(ADMIN_PASSWORD)
            ))
        );
    }

    @Override
    public Set<String> getSecretFields() {
        return Collections.singleton(ADMIN_PASSWORD);
    }

    @Override
    public Set<String> getDestinationFields() {
        return DESTINATION_FIELDS;
    }

    @Override
    public Form getConnectionForm() {
        return new Form("pam-type-" + NAME, Collections.<Field>singletonList(new TextField(ACCOUNT_HOST)));
    }

    @Override
    public void validate(Platform platform) throws GuacamoleClientException {
        try {
            // Any account will do: only the platform settings are checked here
            DatabaseTarget.fromParameters(merge(platform, "validation", null, null));
        }
        catch (IllegalArgumentException e) {
            throw new GuacamoleClientException(e.getMessage());
        }
    }

    @Override
    public PasswordChanger createChanger(Platform platform, Target target) {
        return new DatabasePasswordChanger(database, DatabaseTarget.fromParameters(merge(platform,
                target.getParameters().get("username"), target.getParameters().get("password"),
                target.getAttribute(ACCOUNT_HOST))));
    }

    @Override
    public boolean isTestable() {
        return true;
    }

    @Override
    public PlatformTestResult test(Platform platform) {
        try {
            return database.test(DatabaseTarget.fromParameters(merge(platform, "test", null, null)));
        }
        catch (IllegalArgumentException e) {
            return new PlatformTestResult().failed(e.getMessage());
        }
    }

    /**
     * The MySQL or MariaDB account, as 'name'@'host', or null for other
     * databases' accounts, which their name alone identifies.
     */
    @Override
    public String getAccountDetail(Target target, Platform platform) {
        String host = target.getAttribute(ACCOUNT_HOST);
        return host == null ? null : target.getParameters().get("username") + "@" + host;
    }

    /**
     * Combines the platform settings with the account of a connection, in
     * the form DatabaseTarget reads.
     */
    private static Map<String, String> merge(Platform platform, String username, String password,
            String accountHost) {
        Map<String, String> values = platform.settingsWithSecrets();
        if (username != null)
            values.put(DatabaseTarget.USERNAME, username);
        if (password != null)
            values.put(DatabaseTarget.PASSWORD, password);
        if (accountHost != null)
            values.put(DatabaseTarget.ACCOUNT_HOST, accountHost);
        return values;
    }

}
