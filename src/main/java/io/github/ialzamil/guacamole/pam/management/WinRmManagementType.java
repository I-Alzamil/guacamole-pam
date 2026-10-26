package io.github.ialzamil.guacamole.pam.management;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.apache.guacamole.GuacamoleClientException;
import org.apache.guacamole.form.BooleanField;
import org.apache.guacamole.form.Field;
import org.apache.guacamole.form.Form;
import org.apache.guacamole.form.MultilineField;
import org.apache.guacamole.form.NumericField;
import org.apache.guacamole.form.PasswordField;
import org.apache.guacamole.form.TextField;

import io.github.ialzamil.guacamole.pam.Values;
import io.github.ialzamil.guacamole.pam.db.ConnectionRepository.Target;
import io.github.ialzamil.guacamole.pam.platform.Platform;
import io.github.ialzamil.guacamole.pam.winrm.WinRmClient;
import io.github.ialzamil.guacamole.pam.winrm.WinRmTarget;

/**
 * Sets passwords of local Windows accounts over WinRM (HTTPS, NTLM login
 * bound to the TLS channel). The port, the optional administrator and the
 * certificate authorities issuing the hosts' certificates belong to the
 * platform; each connection gives its host (its own hostname by default),
 * optionally its certificate's fingerprint, and the account is its username.
 */
public class WinRmManagementType implements ManagementType {

    public static final String NAME = "winrm";

    // Platform settings, named as WinRmTarget reads them
    public static final String PORT = WinRmTarget.PORT;
    public static final String ADMIN_USERNAME = WinRmTarget.ADMIN_USERNAME;
    public static final String ADMIN_PASSWORD = WinRmTarget.ADMIN_PASSWORD;
    public static final String CA_CERTIFICATES = WinRmTarget.CA_CERTIFICATES;
    public static final String TRUST_FIRST_CERTIFICATE = WinRmTarget.TRUST_FIRST_CERTIFICATE;

    /**
     * Where the administrator password is sent, and how safely: the CA
     * certificates decide which hosts are trusted with it.
     */
    private static final Set<String> DESTINATION_FIELDS = Collections.unmodifiableSet(
            new HashSet<>(Arrays.asList(PORT, CA_CERTIFICATES, TRUST_FIRST_CERTIFICATE)));

    /**
     * Connection attribute: host to reach over WinRM, the connection's
     * hostname if empty.
     */
    public static final String HOSTNAME = "pam-winrm-hostname";

    /**
     * Connection attribute: SHA-256 fingerprint the host's certificate must
     * match. If empty, the certificate must be issued by one of the
     * platform's CA certificates, or without any, if the platform allows it,
     * the certificate seen first is trusted from then on.
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
            )),
            new Form("winrm-trust", Arrays.<Field>asList(
                new MultilineField(CA_CERTIFICATES),
                new BooleanField(TRUST_FIRST_CERTIFICATE, "true")
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
        Map<String, String> values = platform.settingsWithSecrets();
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
        Map<String, String> values = platform.settingsWithSecrets();

        String hostname = target.getAttribute(HOSTNAME);
        values.put(WinRmTarget.HOSTNAME, hostname != null ? hostname : parameters.get("hostname"));
        values.put(WinRmTarget.USERNAME, parameters.get("username"));
        values.put(WinRmTarget.PASSWORD, parameters.get("password"));
        values.put(WinRmTarget.CERTIFICATE, trustedCertificate(target,
                Values.trimToNull(values.get(CA_CERTIFICATES)) != null));

        return new WinRmPasswordChanger(winrm, WinRmTarget.fromParameters(values));

    }

    /**
     * The certificate to require: the one pinned on the connection, or else
     * (unless the platform trusts certificate authorities, so renewed
     * certificates keep working) the one recorded at the first contact with
     * the host. Only a first contact accepts any certificate.
     */
    private static String trustedCertificate(Target target, boolean byAuthority) {

        String pinned = target.getAttribute(CERTIFICATE);
        if (pinned != null && !pinned.trim().isEmpty())
            return pinned;
        if (byAuthority)
            return null;

        // Only a certificate fingerprint counts: the same state records the
        // SSH host key, should the connection have been managed over SSH
        String recorded = target.getState().getHostKey();
        return recorded != null && recorded.matches("([0-9A-F]{2}:){31}[0-9A-F]{2}") ? recorded : null;

    }


}
