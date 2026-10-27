package io.github.ialzamil.guacamole.pam.management;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.guacamole.GuacamoleClientException;
import org.apache.guacamole.form.BooleanField;
import org.apache.guacamole.form.Field;
import org.apache.guacamole.form.Form;
import org.apache.guacamole.form.MultilineField;
import org.apache.guacamole.form.NumericField;
import org.apache.guacamole.form.TextField;

import io.github.ialzamil.guacamole.pam.Values;
import io.github.ialzamil.guacamole.pam.db.ConnectionRepository.Target;
import io.github.ialzamil.guacamole.pam.platform.Platform;
import io.github.ialzamil.guacamole.pam.ssh.SequenceScript;
import io.github.ialzamil.guacamole.pam.ssh.SshAuthorities;
import io.github.ialzamil.guacamole.pam.ssh.SshClient;
import io.github.ialzamil.guacamole.pam.ssh.SshTarget;

/**
 * Changes passwords by logging in over SSH and running a sequence script.
 */
public class SshManagementType implements ManagementType {

    public static final String NAME = "ssh";

    /**
     * Platform setting: the sequence script.
     */
    public static final String SCRIPT = "script";

    /**
     * Platform setting: SSH port when the connection does not give one.
     */
    public static final String PORT = "port";

    /**
     * Platform setting: whether a host's key is trusted at the first
     * contact, while none is pinned or recorded ("true"), on a platform
     * trusting no certificate authority. Otherwise such a host is refused
     * until its key is pinned on the connection.
     */
    public static final String TRUST_FIRST_KEY = "trust-first-key";

    /**
     * Platform setting: public keys of the certificate authorities whose
     * host certificates are trusted, one per line (see
     * {@link SshAuthorities}). A host presenting a certificate one of them
     * signed, naming the host and valid now, is trusted without a pinned
     * key, so a host given a new key and certificate keeps working.
     */
    public static final String CA_KEYS = "ssh-ca-keys";

    /**
     * Field type of the script, rendered with the script editor.
     */
    public static final String SCRIPT_FIELD_TYPE = "PAM_SCRIPT";

    /**
     * Connection attributes overriding where to log in.
     */
    public static final String SSH_HOSTNAME = "pam-ssh-hostname";
    public static final String SSH_PORT = "pam-ssh-port";

    /**
     * Connection attribute: SHA256 fingerprint the host key must match.
     */
    public static final String SSH_HOST_KEY = "pam-ssh-host-key";

    /**
     * Prefix of SSH host key fingerprints, as OpenSSH prints them.
     */
    private static final String SSH_FINGERPRINT_PREFIX = "SHA256:";

    private static final int DEFAULT_PORT = 22;

    private final SshClient ssh = new SshClient();

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public Collection<Form> getPlatformForms() {
        return Collections.singletonList(new Form("ssh", Arrays.<Field>asList(
            new Field(SCRIPT, SCRIPT_FIELD_TYPE),
            new NumericField(PORT),
            new MultilineField(CA_KEYS),
            new BooleanField(TRUST_FIRST_KEY, "true")
        )));
    }

    @Override
    public Set<String> getSecretFields() {
        return Collections.emptySet();
    }

    @Override
    public Form getConnectionForm() {
        return new Form("pam-type-" + NAME, Arrays.<Field>asList(
            new TextField(SSH_HOSTNAME),
            new NumericField(SSH_PORT),
            new TextField(SSH_HOST_KEY)
        ));
    }

    @Override
    public void validate(Platform platform) throws GuacamoleClientException {

        SequenceScript script = SequenceScript.parse(platform.get(SCRIPT));
        if (!script.isValid())
            throw new GuacamoleClientException("The sequence has errors. " + script.getErrors().get(0));

        if (platform.get(PORT) != null && Values.toPort(platform.get(PORT)) == null)
            throw new GuacamoleClientException("The SSH port must be a number between 1 and 65535.");

        try {
            SshAuthorities.parse(platform.get(CA_KEYS));
        }
        catch (IllegalArgumentException e) {
            throw new GuacamoleClientException(e.getMessage());
        }

    }

    @Override
    public PasswordChanger createChanger(Platform platform, Target target) {

        SequenceScript script = SequenceScript.parse(platform.get(SCRIPT));
        if (!script.isValid())
            throw new IllegalArgumentException("Platform \"" + platform.getName() + "\" has errors. "
                    + script.getErrors().get(0));

        return new SshPasswordChanger(ssh, toSshTarget(platform, target), script);

    }

    /**
     * Builds the SSH login: the connection's credentials, at the overridden
     * host if any, on the overridden port, the SSH connection's own port, the
     * platform port, or 22.
     */
    private static SshTarget toSshTarget(Platform platform, Target target) {

        Map<String, String> parameters = target.getParameters();

        String hostname = target.getAttribute(SSH_HOSTNAME);
        if (hostname == null)
            hostname = Values.emptyToNull(parameters.get("hostname"));
        if (hostname == null)
            throw new IllegalArgumentException("The connection has no hostname. Set the SSH hostname"
                    + " in its password management settings.");

        Integer port = Values.toPort(target.getAttribute(SSH_PORT));
        if (port == null && "ssh".equals(target.getProtocol()))
            port = Values.toPort(parameters.get("port"));
        if (port == null)
            port = Values.toPort(platform.get(PORT));
        if (port == null)
            port = DEFAULT_PORT;

        String username = Values.emptyToNull(parameters.get("username"));
        if (username == null)
            throw new IllegalArgumentException("The connection has no username.");

        String password = Values.emptyToNull(parameters.get("password"));
        String privateKey = Values.emptyToNull(parameters.get("private-key"));
        if (password == null && privateKey == null)
            throw new IllegalArgumentException("The connection has neither a password nor a private key.");

        List<byte[]> authorities = SshAuthorities.parse(platform.get(CA_KEYS));
        boolean trustFirst = "true".equals(platform.get(TRUST_FIRST_KEY)) && authorities.isEmpty();
        return new SshTarget(hostname, port, username, password, privateKey,
                Values.emptyToNull(parameters.get("passphrase")), trustedHostKey(target, !authorities.isEmpty()),
                trustFirst, authorities);

    }

    /**
     * The host key to require: the one pinned on the connection, or else
     * (unless the platform trusts certificate authorities, so a host given
     * a new key keeps working) the one recorded at the first contact with
     * the host (trust on first use, as with SSH's known_hosts, if the
     * platform allows it), kept after it no longer does. Only keys
     * accepted are recorded: a key refused as untrusted never is. Only a
     * first contact may accept any key.
     */
    private static String trustedHostKey(Target target, boolean byAuthority) {

        String pinned = Values.emptyToNull(target.getAttribute(SSH_HOST_KEY));
        if (pinned != null)
            return pinned;
        if (byAuthority)
            return null;

        // Only an SSH key counts: the same state records the certificate of
        // an LDAP target, should the connection have been managed over LDAP
        String recorded = Values.emptyToNull(target.getState().getHostKey());
        return recorded != null && recorded.startsWith(SSH_FINGERPRINT_PREFIX) ? recorded : null;

    }

}
