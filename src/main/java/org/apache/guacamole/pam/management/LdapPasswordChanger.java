package org.apache.guacamole.pam.management;

import org.apache.guacamole.pam.ldap.LdapClient;
import org.apache.guacamole.pam.rotation.ChangeOutcome;
import org.apache.guacamole.pam.ldap.LdapTarget;

/**
 * Changes passwords of directory accounts over LDAP.
 */
public class LdapPasswordChanger implements PasswordChanger {

    private final LdapClient ldap;
    private final LdapTarget target;

    public LdapPasswordChanger(LdapClient ldap, LdapTarget target) {
        this.ldap = ldap;
        this.target = target;
    }

    @Override
    public String getCurrentPassword() {
        return target.getPassword();
    }

    @Override
    public PasswordChanger withCurrentPassword(String password) {
        return new LdapPasswordChanger(ldap, target.withPassword(password));
    }

    @Override
    public ChangeOutcome change(String newPassword) {
        return ldap.changePassword(target, newPassword);
    }

    @Override
    public boolean accepts(String password) throws Exception {
        return ldap.acceptsPassword(target, password);
    }

}
