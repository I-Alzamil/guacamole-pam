package io.github.ialzamil.guacamole.pam.management;

import io.github.ialzamil.guacamole.pam.kerberos.KerberosClient;
import io.github.ialzamil.guacamole.pam.kerberos.KerberosTarget;
import io.github.ialzamil.guacamole.pam.rotation.ChangeOutcome;

/**
 * Changes passwords of Kerberos principals over kpasswd.
 */
public class KerberosPasswordChanger implements PasswordChanger {

    private final KerberosClient kerberos;
    private final KerberosTarget target;

    public KerberosPasswordChanger(KerberosClient kerberos, KerberosTarget target) {
        this.kerberos = kerberos;
        this.target = target;
    }

    @Override
    public String getCurrentPassword() {
        return target.getPassword();
    }

    @Override
    public PasswordChanger withCurrentPassword(String password) {
        return new KerberosPasswordChanger(kerberos, target.withPassword(password));
    }

    @Override
    public ChangeOutcome change(String newPassword) {
        return kerberos.changePassword(target, newPassword);
    }

    @Override
    public boolean accepts(String password) throws Exception {
        return kerberos.acceptsPassword(target, password);
    }

}
