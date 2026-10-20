package org.apache.guacamole.pam.management;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.apache.guacamole.GuacamoleClientException;
import org.apache.guacamole.form.Field;
import org.apache.guacamole.form.Form;
import org.apache.guacamole.form.NumericField;
import org.apache.guacamole.form.PasswordField;
import org.apache.guacamole.form.TextField;
import org.apache.guacamole.pam.db.ConnectionRepository.Target;
import org.apache.guacamole.pam.platform.Platform;
import org.apache.guacamole.pam.winrm.WinRmClient;
import org.apache.guacamole.pam.winrm.WinRmTarget;

/**
 * Sets passwords of local Windows accounts over WinRM (HTTPS, NTLM login
 * bound to the TLS channel). The port and the optional administrator
 * belong to the platform; each connection gives its host (its own hostname
 * by default) and the account is its username.
 */
public class WinRmManagementType implements ManagementType {

    public static final String NAME = "winrm";

    // Platform settings, named as WinRmTarget reads them
    public static final String PORT = WinRmTarget.PORT;
    public static final String ADMIN_USERNAME = WinRmTarget.ADMIN_USERNAME;
    public static final String ADMIN_PASSWORD = WinRmTarget.ADMIN_PASSWORD;

    /**
     * Where the administrator password is sent, and how safely.
     */
    private static final Set<String> DESTINATION_FIELDS = Collections.singleton(PORT);

    /**
     * Connection attribute: host to reach over WinRM, the connection's
     * hostname if empty.
     */
    public static final String HOSTNAME = "pam-winrm-hostname";

    /**
     * Connection attribute: SHA-256 fingerprint the host's certificate must
     * match. If empty, the certificate seen first is trusted from then on.
     */
    public static final String CERTIFICATE = "pam-winrm-certificate";

    private final WinRmClient winrm = new WinRmClient();

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public Collection<Form> getPlatformForms() {
        return Arrays.asList(
            new Form("winrm", Collections.<Field>singletonList(new NumericField(PORT))),
            new Form("winrm-rotation", Arrays.<Field>asList(
                new TextField(ADMIN_USERNAME),
                new PasswordField(ADMIN_PASSWORD)
            ))
        );
    }

    @Override
    public Set<String> getSecretFields() {
        return Collections.singleton(ADMIN_PASSWORD);
    }

    /**
     * The host is each connection's, which only administrators may change.
     */
    @Override
    public Set<String> getDestinationFields() {
        return DESTINATION_FIELDS;
    }

    @Override
    public Form getConnectionForm() {
        return new Form("pam-type-" + NAME, Arrays.<Field>asList(
            new TextField(HOSTNAME),
            new TextField(CERTIFICATE)
        ));
    }

    @Override
    public void validate(Platform platform) throws GuacamoleClientException {
        Map<String, String> values = merge(platform);
        values.put(WinRmTarget.HOSTNAME, "validation");
        values.put(WinRmTarget.USERNAME, "validation");
        try {
            WinRmTarget.fromParameters(values);
        }
        catch (IllegalArgumentException e) {
            throw new GuacamoleClientException(e.getMessage());
        }
    }

    @Override
    public PasswordChanger createChanger(Platform platform, Target target) {

        Map<String, String> parameters = target.getParameters();
        Map<String, String> values = merge(platform);

        String hostname = target.getAttribute(HOSTNAME);
        values.put(WinRmTarget.HOSTNAME, hostname != null ? hostname : parameters.get("hostname"));
        values.put(WinRmTarget.USERNAME, parameters.get("username"));
        values.put(WinRmTarget.PASSWORD, parameters.get("password"));
        values.put(WinRmTarget.CERTIFICATE, trustedCertificate(target));

        return new WinRmPasswordChanger(winrm, WinRmTarget.fromParameters(values));

    }

    /**
     * The certificate to require: the one pinned on the connection, or else
     * the one recorded at the first contact with the host. Only a first
     * contact accepts any certificate.
     */
    private static String trustedCertificate(Target target) {

        String pinned = target.getAttribute(CERTIFICATE);
        if (pinned != null && !pinned.trim().isEmpty())
            return pinned;

        // Only a certificate fingerprint counts: the same state records the
        // SSH host key, should the connection have been managed over SSH
        String recorded = target.getState().getHostKey();
        return recorded != null && recorded.matches("([0-9A-F]{2}:){31}[0-9A-F]{2}") ? recorded : null;

    }

    private static Map<String, String> merge(Platform platform) {
        Map<String, String> values = new HashMap<>(platform.getSettings());
        values.putAll(platform.getSecrets());
        return values;
    }

}
