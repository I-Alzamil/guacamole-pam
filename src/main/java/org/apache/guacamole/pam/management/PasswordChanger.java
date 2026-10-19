package org.apache.guacamole.pam.management;

import org.apache.guacamole.pam.rotation.ChangeOutcome;

/**
 * Changes and verifies the password of one account on one target system.
 */
public interface PasswordChanger {

    /**
     * The password currently stored in Guacamole, possibly null.
     */
    String getCurrentPassword();

    /**
     * Returns a changer acting with a different current password.
     */
    PasswordChanger withCurrentPassword(String password);

    /**
     * Sets the new password on the target. Never throws.
     */
    ChangeOutcome change(String newPassword);

    /**
     * Returns whether the target accepts the given password.
     *
     * @throws Exception
     *     If the target cannot be reached or is not trusted.
     */
    boolean accepts(String password) throws Exception;

}
