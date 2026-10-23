package org.apache.guacamole.pam.management;

import org.apache.guacamole.pam.rotation.ChangeOutcome;
import org.apache.guacamole.pam.tacacs.TacacsClient;
import org.apache.guacamole.pam.tacacs.TacacsTarget;

/**
 * Changes passwords of TACACS+ accounts, over the password change dialogue
 * of the TACACS+ server holding them.
 */
public class TacacsPasswordChanger implements PasswordChanger {

    private final TacacsClient tacacs;
    private final TacacsTarget target;

    public TacacsPasswordChanger(TacacsClient tacacs, TacacsTarget target) {
        this.tacacs = tacacs;
        this.target = target;
    }

    @Override
    public String getCurrentPassword() {
        return target.getPassword();
    }

    @Override
    public PasswordChanger withCurrentPassword(String password) {
        return new TacacsPasswordChanger(tacacs, target.withPassword(password));
    }

    @Override
    public ChangeOutcome change(String newPassword) {
        return tacacs.changePassword(target, newPassword);
    }

    @Override
    public boolean accepts(String password) throws Exception {
        return tacacs.acceptsPassword(target, password);
    }

}
