package org.apache.guacamole.pam.management;

import java.util.HashMap;
import java.util.Map;

import org.apache.guacamole.pam.profile.SequenceScript;
import org.apache.guacamole.pam.rotation.ChangeOutcome;
import org.apache.guacamole.pam.ssh.SshClient;
import org.apache.guacamole.pam.ssh.SshTarget;

/**
 * Changes passwords by running a sequence profile in an SSH shell.
 */
public class SshPasswordChanger implements PasswordChanger {

    private final SshClient ssh;
    private final SshTarget target;
    private final SequenceScript script;

    public SshPasswordChanger(SshClient ssh, SshTarget target, SequenceScript script) {
        this.ssh = ssh;
        this.target = target;
        this.script = script;
    }

    @Override
    public String getCurrentPassword() {
        return target.getPassword();
    }

    @Override
    public PasswordChanger withCurrentPassword(String password) {
        return new SshPasswordChanger(ssh, target.withPassword(password), script);
    }

    @Override
    public ChangeOutcome change(String newPassword) {

        Map<String, String> values = new HashMap<>();
        values.put(SequenceScript.USER, target.getUsername());
        values.put(SequenceScript.HOST, target.getHostname());
        values.put(SequenceScript.OLDPASS, target.getPassword() == null ? "" : target.getPassword());
        values.put(SequenceScript.NEWPASS, newPassword);

        return ssh.runSequence(target, script, values);

    }

    @Override
    public boolean accepts(String password) throws Exception {
        return ssh.acceptsPassword(target, password);
    }

}
