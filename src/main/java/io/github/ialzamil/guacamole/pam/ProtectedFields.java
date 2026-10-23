package io.github.ialzamil.guacamole.pam;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * What only administrators may change. Besides this extension's attributes,
 * the parameters of a managed connection deciding whose password it holds,
 * where guacd sends it and how that server is verified are protected:
 * platforms can act as an administrator of the target (an LDAP, Kerberos or
 * WinRM administrator), and rotate the account named by the connection's
 * username on the host it names. Anyone else able to edit the connection
 * could otherwise point it at another account, then hold it and use that
 * account's new password after the next rotation; or have guacd send the
 * password to a host of their choosing (another host, an RDP gateway, an
 * SFTP server, a VNC repeater), or to any host claiming to be the server
 * (no host key, certificates ignored). So is the password itself, which
 * the platform may not be able to set again once replaced.
 *
 * So are its protocol and the guacd it is opened through: guacd receives
 * every parameter with the password in place of its token, so another guacd
 * would see the password even where its holders may not, and so would a
 * protocol sending it in the clear.
 */
public final class ProtectedFields {

    /**
     * Parameters of managed connections only administrators may change,
     * besides those starting with {@link #MANAGED_PARAMETER_PREFIXES}: the
     * credentials, where they are sent, how the server is verified, and
     * where Telnet types them.
     */
    public static final List<String> MANAGED_PARAMETERS = Collections.unmodifiableList(Arrays.asList(
            "username", "password", "domain", "private-key", "passphrase",
            "hostname", "port", "dest-host", "dest-port", "enable-sftp",
            "host-key", "security", "disable-auth", "ignore-cert", "cert-tofu", "cert-fingerprints",
            "use-ssl", "ca-cert", "client-cert", "client-key",
            "username-regex", "password-regex"));

    /**
     * Prefixes of further protected parameters: the RDP gateway, and SFTP
     * to another server.
     */
    public static final List<String> MANAGED_PARAMETER_PREFIXES = Collections.unmodifiableList(Arrays.asList(
            "gateway-", "sftp-"));

    /**
     * Guacamole's attributes of managed connections only administrators may
     * change: the guacd they are opened through.
     */
    public static final List<String> MANAGED_ATTRIBUTES =
            Collections.unmodifiableList(Arrays.asList("guacd-hostname", "guacd-port", "guacd-encryption"));

    private ProtectedFields() {
    }

    /**
     * Whether any of the given attributes differs. A missing attribute, an
     * empty value, "false" and "[]" are alike (unset). Stored attributes are
     * null for a new object.
     */
    public static boolean attributesChanged(List<String> names, Map<String, String> stored,
            Map<String, String> updated) {
        for (String name : names) {
            if (!Objects.equals(normalizeAttribute(stored, name), normalizeAttribute(updated, name)))
                return true;
        }
        return false;
    }

    /**
     * Whether a parameter of managed connections is protected.
     */
    public static boolean isManagedParameter(String name) {
        if (MANAGED_PARAMETERS.contains(name))
            return true;
        for (String prefix : MANAGED_PARAMETER_PREFIXES) {
            if (name.startsWith(prefix))
                return true;
        }
        return false;
    }

    /**
     * Whether any protected parameter of managed connections differs. A
     * missing parameter and an empty value are alike.
     */
    public static boolean managedParametersChanged(Map<String, String> stored, Map<String, String> updated) {
        Set<String> names = new HashSet<>(stored.keySet());
        names.addAll(updated.keySet());
        for (String name : names) {
            if (isManagedParameter(name)
                    && !Objects.equals(normalizeParameter(stored, name), normalizeParameter(updated, name)))
                return true;
        }
        return false;
    }

    /**
     * Whether a connection with these attributes is managed by a platform.
     */
    public static boolean isManaged(Map<String, String> attributes) {
        return normalizeAttribute(attributes, PamAttributes.PLATFORM) != null;
    }

    private static String normalizeAttribute(Map<String, String> attributes, String name) {
        String value = attributes == null ? null : attributes.get(name);
        if (value == null || value.trim().isEmpty() || value.equals("false") || value.equals("[]"))
            return null;
        return value.trim();
    }

    private static String normalizeParameter(Map<String, String> parameters, String name) {
        String value = parameters == null ? null : parameters.get(name);
        return value == null || value.isEmpty() ? null : value;
    }

}
