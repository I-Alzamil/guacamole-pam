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
import org.apache.guacamole.form.NumericField;
import org.apache.guacamole.form.PasswordField;
import org.apache.guacamole.form.TextField;

import io.github.ialzamil.guacamole.pam.db.ConnectionRepository.Target;
import io.github.ialzamil.guacamole.pam.ldap.LdapClient;
import io.github.ialzamil.guacamole.pam.ldap.LdapTarget;
import io.github.ialzamil.guacamole.pam.platform.Platform;

/**
 * Changes passwords of directory accounts over LDAP: standard directories
 * through the password modify extended operation, Active Directory through
 * unicodePwd. The directory server and the optional rotation account belong
 * to the platform; each connection gives the DN of its account.
 */
public class LdapManagementType implements ManagementType {

    public static final String NAME = "ldap";

    // Platform settings, named as LdapTarget reads them
    public static final String HOSTNAME = LdapTarget.HOSTNAME;
    public static final String PORT = LdapTarget.PORT;
    public static final String ENCRYPTION = LdapTarget.ENCRYPTION;
    public static final String CERTIFICATE = LdapTarget.CERTIFICATE;
    public static final String DIRECTORY_TYPE = LdapTarget.DIRECTORY_TYPE;
    public static final String ADMIN_DN = LdapTarget.ADMIN_DN;
    public static final String ADMIN_PASSWORD = LdapTarget.ADMIN_PASSWORD;

    /**
     * Where the administrator password is sent, and how safely.
     */
    private static final Set<String> DESTINATION_FIELDS = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
            HOSTNAME, PORT, ENCRYPTION, CERTIFICATE)));

    /**
     * Connection attribute: DN of the account.
     */
    public static final String LDAP_DN = "pam-ldap-dn";

    private final LdapClient ldap = new LdapClient();

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public Collection<Form> getPlatformForms() {
        return Arrays.asList(
            new Form("ldap-server", Arrays.<Field>asList(
                new TextField(HOSTNAME),
                new NumericField(PORT),
                new EnumField(ENCRYPTION, Arrays.asList("", LdapTarget.ENCRYPTION_STARTTLS, LdapTarget.ENCRYPTION_NONE)),
                new TextField(CERTIFICATE),
                new EnumField(DIRECTORY_TYPE, Arrays.asList("", LdapTarget.DIRECTORY_ACTIVE_DIRECTORY))
            )),
            new Form("ldap-rotation", Arrays.<Field>asList(
                new TextField(ADMIN_DN),
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
        return new Form("pam-type-" + NAME, Collections.<Field>singletonList(new TextField(LDAP_DN)));
    }

    @Override
    public void validate(Platform platform) throws GuacamoleClientException {
        try {
            // Any DN will do: only the platform settings are checked here
            LdapTarget.fromParameters(merge(platform, "cn=validation", null, null));
        }
        catch (IllegalArgumentException e) {
            throw new GuacamoleClientException(e.getMessage());
        }
    }

    @Override
    public PasswordChanger createChanger(Platform platform, Target target) {

        String dn = target.getAttribute(LDAP_DN);
        if (dn == null)
            throw new IllegalArgumentException("The connection has no account DN. Set it in its password"
                    + " management settings.");

        return new LdapPasswordChanger(ldap, LdapTarget.fromParameters(merge(platform, dn,
                target.getParameters().get("username"), target.getParameters().get("password"))));

    }

    @Override
    public boolean isTestable() {
        return true;
    }

    @Override
    public PlatformTestResult test(Platform platform) {
        try {
            return ldap.test(LdapTarget.fromParameters(merge(platform, "cn=test", null, null)));
        }
        catch (IllegalArgumentException e) {
            return new PlatformTestResult().failed(e.getMessage());
        }
    }

    @Override
    public String getAccountDetail(Target target) {
        return target.getAttribute(LDAP_DN);
    }

    /**
     * Combines the platform settings with the account of a connection, in
     * the form LdapTarget reads.
     */
    private static Map<String, String> merge(Platform platform, String dn, String username, String password) {
        Map<String, String> values = platform.settingsWithSecrets();
        values.put(LdapTarget.USER_DN, dn);
        if (username != null)
            values.put(LdapTarget.USERNAME, username);
        if (password != null)
            values.put(LdapTarget.PASSWORD, password);
        return values;
    }

}
