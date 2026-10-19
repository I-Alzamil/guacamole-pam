package org.apache.guacamole.pam.ssh;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.regex.Pattern;

import com.jcraft.jsch.ChannelShell;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Session;

import org.apache.guacamole.pam.profile.SequenceScript;
import org.apache.guacamole.pam.rotation.ChangeOutcome;
import org.apache.guacamole.pam.profile.SequenceScript.Step;

/**
 * Runs sequence scripts in an interactive SSH shell, and checks whether a
 * password is accepted by the target.
 */
public class SshClient {

    private static final int CONNECT_TIMEOUT_MS = 15000;

    /**
     * How long output must stay quiet after the last step before the shell
     * is closed, and the upper bound on that wait.
     */
    private static final long SETTLE_QUIET_MS = 500;
    private static final long SETTLE_MAX_MS = 3000;

    private static final long POLL_INTERVAL_MS = 50;

    /**
     * Amount of output kept for the transcript shown on failure.
     */
    private static final int TRANSCRIPT_LIMIT = 2000;

    private static final Pattern ANSI_ESCAPE = Pattern.compile(
            "\u001B\\[[0-?]*[ -/]*[@-~]"           // CSI sequences (colors, cursor moves)
          + "|\u001B\\][^\u0007\u001B]*(\u0007|\u001B\\\\)" // OSC sequences (window title)
          + "|\u001B[@-Z\\\\-_]");                // other two-character escapes

    /**
     * Logs in with the target's current credentials and runs the given
     * script. Never throws: every failure is reported in the outcome.
     */
    public ChangeOutcome runSequence(SshTarget target, SequenceScript script,
            Map<String, String> values) {

        PinnedHostKeyRepository hostKeys = new PinnedHostKeyRepository(target.getPinnedHostKey());
        Session session = null;
        ChannelShell channel = null;
        Output output = new Output(values);
        boolean newPasswordSent = false;

        try {

            session = openSession(target, target.getPassword(), true, hostKeys);

            channel = (ChannelShell) session.openChannel("shell");
            channel.setPty(true);
            channel.setPtyType("dumb");
            InputStream in = channel.getInputStream();
            OutputStream out = channel.getOutputStream();
            channel.connect(CONNECT_TIMEOUT_MS);

            int timeout = SequenceScript.DEFAULT_TIMEOUT;

            for (Step step : script.getSteps()) {
                switch (step.getType()) {

                    case TIMEOUT:
                        timeout = Integer.parseInt(step.getValue());
                        break;

                    case SEND:
                        output.pump(in);
                        output.startStep();
                        String text = SequenceScript.substitute(step.getValue(), values, false);
                        out.write((text + "\r").getBytes(StandardCharsets.UTF_8));
                        out.flush();
                        newPasswordSent |= step.sendsNewPassword();
                        break;

                    case EXPECT:
                    case REGEX:
                        boolean regex = step.getType() == SequenceScript.StepType.REGEX;
                        String value = SequenceScript.substitute(step.getValue(), values, regex);
                        Pattern pattern = Pattern.compile(regex ? value : Pattern.quote(value));
                        if (!output.await(in, channel, pattern, timeout * 1000L))
                            return new ChangeOutcome(false, newPasswordSent,
                                    "Line " + step.getLine() + ": did not see \"" + step.getValue()
                                    + "\" within " + timeout + " seconds.",
                                    output.transcript(), hostKeys.getPresentedFingerprint());
                        break;

                }
            }

            output.settle(in, channel);
            return new ChangeOutcome(true, newPasswordSent, null,
                    output.transcript(), hostKeys.getPresentedFingerprint());

        }
        catch (JSchException | IOException e) {
            return new ChangeOutcome(false, newPasswordSent, describe(e, hostKeys),
                    output.transcript(), hostKeys.getPresentedFingerprint());
        }
        catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return new ChangeOutcome(false, newPasswordSent, "Interrupted.",
                    output.transcript(), hostKeys.getPresentedFingerprint());
        }
        finally {
            if (channel != null)
                channel.disconnect();
            if (session != null)
                session.disconnect();
        }

    }

    /**
     * Returns whether the target accepts the given password, using password
     * authentication only.
     *
     * @throws JSchException
     *     If the target could not be reached, or its host key does not match
     *     the pinned fingerprint.
     */
    public boolean acceptsPassword(SshTarget target, String password) throws JSchException {

        if (password == null || password.isEmpty())
            return false;

        Session session = null;
        try {
            session = openSession(target, password, false, new PinnedHostKeyRepository(target.getPinnedHostKey()));
            return true;
        }
        catch (JSchException e) {
            if (isAuthFailure(e))
                return false;
            throw e;
        }
        finally {
            if (session != null)
                session.disconnect();
        }

    }

    private Session openSession(SshTarget target, String password, boolean allowKey,
            PinnedHostKeyRepository hostKeys) throws JSchException {

        JSch jsch = new JSch();
        jsch.setHostKeyRepository(hostKeys);

        boolean useKey = allowKey && target.getPrivateKey() != null && !target.getPrivateKey().isEmpty();
        if (useKey) {
            byte[] passphrase = target.getPassphrase() == null || target.getPassphrase().isEmpty()
                    ? null : target.getPassphrase().getBytes(StandardCharsets.UTF_8);
            jsch.addIdentity("connection-key", target.getPrivateKey().getBytes(StandardCharsets.UTF_8),
                    null, passphrase);
        }

        Session session = jsch.getSession(target.getUsername(), target.getHostname(), target.getPort());
        session.setConfig("StrictHostKeyChecking", "yes");
        session.setConfig("PreferredAuthentications", useKey
                ? "publickey,password,keyboard-interactive" : "password,keyboard-interactive");
        if (password != null && !password.isEmpty())
            session.setPassword(password);

        session.connect(CONNECT_TIMEOUT_MS);
        return session;

    }

    private static boolean isAuthFailure(JSchException e) {
        String message = e.getMessage() == null ? "" : e.getMessage().toLowerCase();
        return message.contains("auth fail") || message.contains("auth cancel")
                || message.contains("too many authentication failures");
    }

    private static String describe(Exception e, PinnedHostKeyRepository hostKeys) {

        String message = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
        String lower = message.toLowerCase();

        if (lower.contains("hostkey has been changed") || lower.contains("reject hostkey"))
            return "The host key " + hostKeys.getPresentedFingerprint()
                    + " does not match the pinned fingerprint. No credentials were sent.";
        if (e instanceof JSchException && isAuthFailure((JSchException) e))
            return "The target rejected the current credentials.";

        return "SSH error: " + message;

    }

    /**
     * Output received from the shell: the text seen since the last send,
     * which expectations are matched against, plus a bounded transcript.
     */
    private static final class Output {

        private final Map<String, String> values;
        private final StringBuilder raw = new StringBuilder();
        private final StringBuilder transcript = new StringBuilder();
        private int stepStart = 0;
        private final byte[] buffer = new byte[4096];

        Output(Map<String, String> values) {
            this.values = values;
        }

        /**
         * Reads everything available without blocking. Returns whether any
         * output arrived.
         */
        boolean pump(InputStream in) throws IOException {
            boolean received = false;
            while (in.available() > 0) {
                int length = in.read(buffer, 0, Math.min(buffer.length, in.available()));
                if (length <= 0)
                    break;
                String text = new String(buffer, 0, length, StandardCharsets.UTF_8);
                raw.append(text);
                transcript.append(text);
                if (transcript.length() > TRANSCRIPT_LIMIT * 2)
                    transcript.delete(0, transcript.length() - TRANSCRIPT_LIMIT);
                received = true;
            }
            return received;
        }

        void startStep() {
            stepStart = raw.length();
        }

        boolean await(InputStream in, ChannelShell channel, Pattern pattern, long timeoutMs)
                throws IOException, InterruptedException {

            long deadline = System.currentTimeMillis() + timeoutMs;
            while (true) {
                pump(in);
                if (pattern.matcher(clean(raw.substring(stepStart))).find())
                    return true;
                if (channel.isClosed() && in.available() == 0)
                    return false;
                if (System.currentTimeMillis() >= deadline)
                    return false;
                Thread.sleep(POLL_INTERVAL_MS);
            }

        }

        /**
         * Waits for output to go quiet, so the final command has a chance to
         * finish before the shell is closed.
         */
        void settle(InputStream in, ChannelShell channel) throws IOException, InterruptedException {
            long end = System.currentTimeMillis() + SETTLE_MAX_MS;
            long lastOutput = System.currentTimeMillis();
            while (System.currentTimeMillis() < end && !channel.isClosed()) {
                if (pump(in))
                    lastOutput = System.currentTimeMillis();
                else if (System.currentTimeMillis() - lastOutput >= SETTLE_QUIET_MS)
                    return;
                Thread.sleep(POLL_INTERVAL_MS);
            }
        }

        String transcript() {
            String text = clean(transcript.toString());
            if (text.length() > TRANSCRIPT_LIMIT)
                text = text.substring(text.length() - TRANSCRIPT_LIMIT);
            for (String key : new String[] { SequenceScript.OLDPASS, SequenceScript.NEWPASS }) {
                String secret = values.get(key);
                if (secret != null && !secret.isEmpty())
                    text = text.replace(secret, "******");
            }
            return text.trim();
        }

        private static String clean(String text) {
            return ANSI_ESCAPE.matcher(text).replaceAll("").replace("\r", "");
        }

    }

}
