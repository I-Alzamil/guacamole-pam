package org.apache.guacamole.pam.management;

import java.util.Collection;
import java.util.Collections;
import java.util.Set;

import org.apache.guacamole.GuacamoleClientException;
import org.apache.guacamole.form.Form;
import org.apache.guacamole.pam.db.ConnectionRepository.Target;
import org.apache.guacamole.pam.platform.Platform;

/**
 * A way of managing passwords, such as over SSH or LDAP. Adding a type here
 * (and to {@link ManagementTypes}) is all it takes to offer it: the settings
 * page and the connection editor build their forms from these definitions.
 *

 * The account being managed is named by the connection (its username, or an
 * attribute of the type, such as an LDAP DN), and its current password is the
 * connection's "password" parameter.
 */
public interface ManagementType {

    /**
     * Unique name, such as "ssh". Also the suffix of the translation
     * namespace "PAM_TYPE_&lt;NAME&gt;" of its fields.
     */
    String getName();

    /**
     * Settings of platforms of this type.
     */
    Collection<Form> getPlatformForms();

    /**
     * Names of the platform fields holding secrets, which are stored
     * separately and never sent to clients.
     */
    Set<String> getSecretFields();

    /**
     * Names of the platform fields deciding where its secrets are sent, and
     * how safely: server, port, encryption, trusted certificate. Changing
     * one needs the secrets entered again, so a stored secret is never sent
     * to a server it was not entered for.
     */
    default Set<String> getDestinationFields() {
        return Collections.emptySet();
    }

    /**
     * Connection attributes needed by this type on each managed connection.
     * Named "pam-type-&lt;name&gt;", so the editor shows it only for
     * connections on a platform of this type.
     */
    Form getConnectionForm();

    /**
     * Checks the settings of a platform of this type.
     *
     * @throws GuacamoleClientException
     *     If the settings are incomplete or invalid.
     */
    void validate(Platform platform) throws GuacamoleClientException;

    /**
     * Builds the changer for a connection on a platform of this type.
     *
     * @throws IllegalArgumentException
     *     If the connection is not configured well enough to rotate.
     */
    PasswordChanger createChanger(Platform platform, Target target);

    /**
     * Extra identification of the account shown to users requesting its
     * password, such as an LDAP DN, or null.
     */
    default String getAccountDetail(Target target) {
        return null;
    }

}
