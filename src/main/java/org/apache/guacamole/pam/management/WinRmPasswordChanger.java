package org.apache.guacamole.pam.management;

import org.apache.guacamole.pam.rotation.ChangeOutcome;
import org.apache.guacamole.pam.winrm.WinRmClient;
import org.apache.guacamole.pam.winrm.WinRmTarget;

/**
 * Sets passwords of local Windows accounts over WinRM. When no certificate
 * is trusted yet, the first one the host presents is required for the rest
 * of the rotation, and recorded with its outcome.
 */
public class WinRmPasswordChanger implements PasswordChanger {

    private final WinRmClient winrm;
    private volatile WinRmTarget target;

    public WinRmPasswordChanger(WinRmClient winrm, WinRmTarget target) {
        this.winrm = winrm;
        this.target = target;
    }

    @Override
    public String getCurrentPassword() {
        return target.getPassword();
    }

    @Override
    public PasswordChanger withCurrentPassword(String password) {
        return new WinRmPasswordChanger(winrm, target.withPassword(password));
    }

    @Override
    public ChangeOutcome change(String newPassword) {
        ChangeOutcome outcome = winrm.changePassword(target, newPassword);
        trust(outcome.getHostKey());
        return outcome;
    }

    @Override
    public boolean accepts(String password) throws Exception {
        WinRmClient.Check check = winrm.acceptsPassword(target, password);
        trust(check.getCertificate());
        return check.isAccepted();
    }

    private void trust(String presented) {
        if (target.getCertificate() == null && presented != null)
            target = target.withCertificate(presented);
    }

}
