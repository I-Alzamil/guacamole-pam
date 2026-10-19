package org.apache.guacamole.pam;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * What only administrators may change. Besides this extension's attributes,
 * the parameters naming the account and host of a managed connection are
 * protected: platforms can act as an administrator of the target (an LDAP,
 * Kerberos or WinRM administrator), and rotate the account named by the
 * connection's username on the host it names. Anyone else able to edit the
 * connection, who can read its password, could otherwise point it at
 * another account and read that account's new password after the next
 * rotation, or send the platform's administrator login to a host of their
 * choosing.
 */
public final class ProtectedFields {

    /**
     * Parameters of managed connections only administrators may change.
     */
    public static final List<String> MANAGED_PARAMETERS =
            Collections.unmodifiableList(Arrays.asList("username", "hostname", "port"));

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
     * Whether any of the given parameters differs. A missing parameter and
     * an empty value are alike.
     */
    public static boolean parametersChanged(List<String> names, Map<String, String> stored,
            Map<String, String> updated) {
        for (String name : names) {
            if (!Objects.equals(normalizeParameter(stored, name), normalizeParameter(updated, name)))
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
