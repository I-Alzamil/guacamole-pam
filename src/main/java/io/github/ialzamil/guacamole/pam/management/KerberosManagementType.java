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
import io.github.ialzamil.guacamole.pam.kerberos.KerberosClient;
import io.github.ialzamil.guacamole.pam.kerberos.KerberosTarget;
import io.github.ialzamil.guacamole.pam.platform.Platform;

/**
 * Changes passwords of Kerberos principals over kpasswd (RFC 3244), in MIT
 * Kerberos, Heimdal or Active Directory realms. The realm, its servers and
 * the optional admin principal belong to the platform; each connection's
 * principal is its username, unless it gives one.
 */
public class KerberosManagementType implements ManagementType {

    public static final String NAME = "kerberos";

    // Platform settings, named as KerberosTarget reads them
    public static final String REALM = KerberosTarget.REALM;
    public static final String KDC = KerberosTarget.KDC;
    public static final String KDC_PORT = KerberosTarget.KDC_PORT;
    public static final String KPASSWD_SERVER = KerberosTarget.KPASSWD_SERVER;
    public static final String KPASSWD_PORT = KerberosTarget.KPASSWD_PORT;
    public static final String ADMIN_PRINCIPAL = KerberosTarget.ADMIN_PRINCIPAL;
    public static final String ADMIN_PASSWORD = KerberosTarget.ADMIN_PASSWORD;

    /**
     * Where the administrator password is sent, and how safely.
     */
    private static final Set<String> DESTINATION_FIELDS = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
            REALM, KDC, KDC_PORT, KPASSWD_SERVER, KPASSWD_PORT)));

    /**
     * Connection attribute: principal of the account, the connection's
     * username if empty.
     */
    public static final String PRINCIPAL = "pam-kerberos-principal";

    private final KerberosClient kerberos = new KerberosClient();

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public Collection<Form> getPlatformForms() {
        return Arrays.asList(
            new Form("kerberos-server", Arrays.<Field>asList(
                new TextField(REALM),
                new TextField(KDC),
                new NumericField(KDC_PORT),
                new TextField(KPASSWD_SERVER),
                new NumericField(KPASSWD_PORT)
            )),
            new Form("kerberos-rotation", Arrays.<Field>asList(
                new TextField(ADMIN_PRINCIPAL),
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
        return new Form("pam-type-" + NAME, Collections.<Field>singletonList(new TextField(PRINCIPAL)));
    }

    @Override
    public void validate(Platform platform) throws GuacamoleClientException {
        try {
            // Any principal will do: only the platform settings are checked here
            KerberosTarget.fromParameters(merge(platform, "validation", null));
        }
        catch (IllegalArgumentException e) {
            throw new GuacamoleClientException(e.getMessage());
        }
    }

    @Override
    public PasswordChanger createChanger(Platform platform, Target target) {
        return new KerberosPasswordChanger(kerberos, KerberosTarget.fromParameters(
                merge(platform, principalOf(target), target.getParameters().get("password"))));
    }

    @Override
    public boolean isTestable() {
        return true;
    }

    @Override
    public PlatformTestResult test(Platform platform) {
        try {
            return kerberos.test(KerberosTarget.fromParameters(merge(platform, "test", null)));
        }
        catch (IllegalArgumentException e) {
            return new PlatformTestResult().failed(e.getMessage());
        }
    }

    @Override
    public String getAccountDetail(Target target) {
        return target.getAttribute(PRINCIPAL);
    }

    /**
     * The connection's principal, or its username.
     */
    private static String principalOf(Target target) {
        String principal = target.getAttribute(PRINCIPAL);
        return principal != null ? principal : target.getParameters().get("username");
    }

    /**
     * Combines the platform settings with the account of a connection, in
     * the form KerberosTarget reads.
     */
    private static Map<String, String> merge(Platform platform, String principal, String password) {
        Map<String, String> values = platform.settingsWithSecrets();
        if (principal != null)
            values.put(KerberosTarget.PRINCIPAL, principal);
        if (password != null)
            values.put(KerberosTarget.PASSWORD, password);
        return values;
    }

}
