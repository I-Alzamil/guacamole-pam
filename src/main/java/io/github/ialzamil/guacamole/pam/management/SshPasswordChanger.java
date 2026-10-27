package io.github.ialzamil.guacamole.pam.management;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import io.github.ialzamil.guacamole.pam.ssh.SequenceScript;
import io.github.ialzamil.guacamole.pam.rotation.ChangeOutcome;
import io.github.ialzamil.guacamole.pam.ssh.SshClient;
import io.github.ialzamil.guacamole.pam.ssh.SshTarget;

/**
 * Changes passwords by running a sequence profile in an SSH shell. A rotation
 * connects several times (an earlier pending password, the change, then
 * both passwords checked): a host key trusted on first use is required of
 * the connections after the first, as WinRM does with certificates.
 */
public class SshPasswordChanger implements PasswordChanger {

    private final SshClient ssh;
    private final SshTarget target;
    private final SequenceScript script;

    /**
     * The host key accepted first in this rotation, shared with the
     * changers made from this one, or null.
     */
    private final AtomicReference<String> firstKey;

    public SshPasswordChanger(SshClient ssh, SshTarget target, SequenceScript script) {
        this(ssh, target, script, new AtomicReference<>());
    }

    private SshPasswordChanger(SshClient ssh, SshTarget target, SequenceScript script,
            AtomicReference<String> firstKey) {
        this.ssh = ssh;
        this.target = target;
        this.script = script;
        this.firstKey = firstKey;
    }

    /**
     * The target, requiring the key accepted earlier in this rotation if
     * none is pinned.
     */
    private SshTarget pinned() {
        String key = firstKey.get();
        return key != null && target.getPinnedHostKey() == null ? target.withPinnedHostKey(key) : target;
    }

    @Override
    public String getCurrentPassword() {
        return target.getPassword();
    }

    @Override
    public PasswordChanger withCurrentPassword(String password) {
        return new SshPasswordChanger(ssh, target.withPassword(password), script, firstKey);
    }

    @Override
    public ChangeOutcome change(String newPassword) {

        Map<String, String> values = new HashMap<>();
        values.put(SequenceScript.USER, target.getUsername());
        values.put(SequenceScript.HOST, target.getHostname());
        values.put(SequenceScript.OLDPASS, target.getPassword() == null ? "" : target.getPassword());
        values.put(SequenceScript.NEWPASS, newPassword);

        ChangeOutcome outcome = ssh.runSequence(pinned(), script, values);
        if (outcome.getHostKey() != null)
            firstKey.compareAndSet(null, outcome.getHostKey());
        return outcome;

    }

    @Override
    public boolean accepts(String password) throws Exception {
        return ssh.acceptsPassword(pinned(), password, key -> firstKey.compareAndSet(null, key));
    }

}
