package io.github.ialzamil.guacamole.pam.management;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.apache.guacamole.GuacamoleClientException;
import org.apache.guacamole.form.Field;
import org.apache.guacamole.form.Form;
import org.apache.guacamole.form.NumericField;
import org.apache.guacamole.form.PasswordField;
import org.apache.guacamole.form.TextField;

import io.github.ialzamil.guacamole.pam.db.ConnectionRepository.Target;
import io.github.ialzamil.guacamole.pam.platform.Platform;
import io.github.ialzamil.guacamole.pam.tacacs.TacacsClient;
import io.github.ialzamil.guacamole.pam.tacacs.TacacsTarget;

/**
 * Changes passwords of accounts held by a TACACS+ server (RFC 8907), over
 * its password change dialogue, with the account's current password: only
 * on servers allowing it. The servers and their shared secret belong to the
 * platform; each connection's account is its username, unless it gives one.
 */
public class TacacsManagementType implements ManagementType {

    public static final String NAME = "tacacs";

    // Platform settings, named as TacacsTarget reads them
    public static final String SERVER = TacacsTarget.SERVER;
    public static final String PORT = TacacsTarget.PORT;
    public static final String BACKUP_SERVER = TacacsTarget.BACKUP_SERVER;
    public static final String SECRET = TacacsTarget.SECRET;

    /**
     * Where the shared secret, and passwords, are sent.
     */
    private static final Set<String> DESTINATION_FIELDS = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
            SERVER, PORT, BACKUP_SERVER)));

    /**
     * Connection attribute: TACACS+ username of the account, the
     * connection's username if empty.
     */
    public static final String USERNAME = "pam-tacacs-username";

    private final TacacsClient tacacs = new TacacsClient();

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public Collection<Form> getPlatformForms() {
        return Collections.singletonList(
            new Form("tacacs-server", Arrays.<Field>asList(
                new TextField(SERVER),
                new NumericField(PORT),
                new TextField(BACKUP_SERVER),
                new PasswordField(SECRET)
            ))
        );
    }

    @Override
    public Set<String> getSecretFields() {
        return Collections.singleton(SECRET);
    }

    @Override
    public Set<String> getDestinationFields() {
        return DESTINATION_FIELDS;
    }

    @Override
    public Form getConnectionForm() {
        return new Form("pam-type-" + NAME, Collections.<Field>singletonList(new TextField(USERNAME)));
    }

    @Override
    public void validate(Platform platform) throws GuacamoleClientException {
        try {
            // Any account will do: only the platform settings are checked here
            TacacsTarget.fromParameters(merge(platform, "validation", null));
        }
        catch (IllegalArgumentException e) {
            throw new GuacamoleClientException(e.getMessage());
        }
    }

    @Override
    public PasswordChanger createChanger(Platform platform, Target target) {
        return new TacacsPasswordChanger(tacacs, TacacsTarget.fromParameters(
                merge(platform, usernameOf(target), target.getParameters().get("password"))));
    }

    @Override
    public boolean isTestable() {
        return true;
    }

    @Override
    public PlatformTestResult test(Platform platform) {
        try {
            return tacacs.test(TacacsTarget.fromParameters(merge(platform, "test", null)));
        }
        catch (IllegalArgumentException e) {
            return new PlatformTestResult().failed(e.getMessage());
        }
    }

    /**
     * The connection's TACACS+ username, or its username.
     */
    private static String usernameOf(Target target) {
        String username = target.getAttribute(USERNAME);
        return username != null ? username : target.getParameters().get("username");
    }

    /**
     * Combines the platform settings with the account of a connection, in
     * the form TacacsTarget reads.
     */
    private static Map<String, String> merge(Platform platform, String username, String password) {
        Map<String, String> values = platform.settingsWithSecrets();
        if (username != null)
            values.put(TacacsTarget.USERNAME, username);
        if (password != null)
            values.put(TacacsTarget.PASSWORD, password);
        return values;
    }

}
