package io.github.ialzamil.guacamole.pam.ssh;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.jcraft.jsch.ChannelShell;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Session;

import io.github.ialzamil.guacamole.pam.rotation.ChangeOutcome;
import io.github.ialzamil.guacamole.pam.ssh.SequenceScript.Choice;
import io.github.ialzamil.guacamole.pam.ssh.SequenceScript.Step;

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
     * Most output since the last send that expectations are matched
     * against: its end, where prompts are. Bounds memory and matching on a
     * target sending endless output.
     */
    private static final int MAX_STEP_OUTPUT = 64 * 1024;

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

        PinnedHostKeyRepository hostKeys;
        try {
            hostKeys = hostKeys(target);
        }
        catch (IllegalArgumentException e) {
            return new ChangeOutcome(false, false, e.getMessage(), null, null);
        }
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

            List<Step> steps = script.getSteps();
            for (int index = 0; index < steps.size(); index++) {
                Step step = steps.get(index);
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
                                    output.transcript(), hostKeys.getTrustedFingerprint());
                        break;

                    case CASE:
                        Choice choice = step.getChoice();

                        // Reached from the case before: that case is done
                        if (choice.getCases().get(0) != index) {
                            index = choice.getEnd();
                            break;
                        }

                        List<Pattern> patterns = new ArrayList<>();
                        for (int c : choice.getCases())
                            patterns.add(Pattern.compile(
                                    SequenceScript.substitute(steps.get(c).getValue(), values, true)));
                        int matched = output.awaitAny(in, channel, patterns, timeout * 1000L);
                        if (matched < 0)
                            return new ChangeOutcome(false, newPasswordSent,
                                    "Line " + step.getLine() + ": the output matched none of the cases"
                                    + " within " + timeout + " seconds.",
                                    output.transcript(), hostKeys.getTrustedFingerprint());
                        index = choice.getCases().get(matched);
                        break;

                    case END:
                        break;

                    case FAIL:
                        output.settle(in, channel);
                        return new ChangeOutcome(false, newPasswordSent,
                                "Line " + step.getLine() + ": " + step.getValue(),
                                output.transcript(), hostKeys.getTrustedFingerprint());

                }
            }

            output.settle(in, channel);
            return new ChangeOutcome(true, newPasswordSent, null,
                    output.transcript(), hostKeys.getTrustedFingerprint());

        }
        catch (JSchException | IOException e) {
            return new ChangeOutcome(false, newPasswordSent, describe(e, hostKeys),
                    output.transcript(), hostKeys.getTrustedFingerprint());
        }
        catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return new ChangeOutcome(false, newPasswordSent, "Interrupted.",
                    output.transcript(), hostKeys.getTrustedFingerprint());
        }
        catch (RuntimeException e) {
            return new ChangeOutcome(false, newPasswordSent, "The sequence failed: " + e.getMessage(),
                    output.transcript(), hostKeys.getTrustedFingerprint());
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
        return acceptsPassword(target, password, null);
    }

    /**
     * As {@link #acceptsPassword(SshTarget, String)}, telling the given
     * consumer, if any, the fingerprint of the host key accepted.
     */
    public boolean acceptsPassword(SshTarget target, String password, Consumer<String> trustedKey)
            throws JSchException {

        if (password == null || password.isEmpty())
            return false;

        PinnedHostKeyRepository hostKeys = hostKeys(target);
        Session session = null;
        try {
            session = openSession(target, password, false, hostKeys);
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
            if (trustedKey != null && hostKeys.getTrustedFingerprint() != null)
                trustedKey.accept(hostKeys.getTrustedFingerprint());
        }

    }

    private static PinnedHostKeyRepository hostKeys(SshTarget target) {
        return new PinnedHostKeyRepository(target.getPinnedHostKey(), target.isTrustFirstKey(),
                target.getHostname(), target.getPort(), target.getAuthorities());
    }

    /**
     * The host key algorithms JSch offers: host certificates first if
     * certificate authorities are trusted, so a host presents one if it
     * has one, otherwise plain keys only, as no certificate could be
     * trusted.
     */
    private static String hostKeyAlgorithms(boolean certificates) {
        List<String> algorithms = new ArrayList<>();
        for (String algorithm : JSch.getConfig("server_host_key").split(",")) {
            if (certificates || !algorithm.contains("-cert-"))
                algorithms.add(algorithm);
        }
        return String.join(",", algorithms);
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
        session.setConfig("server_host_key", hostKeyAlgorithms(hostKeys.hasAuthorities()));
        // A certificate the authorities do not vouch for is refused, saying
        // why, not checked as a plain key
        session.setConfig("host_certificate_to_key_fallback", "no");
        session.setConfig("PreferredAuthentications", useKey
                ? "publickey,password,keyboard-interactive" : "password,keyboard-interactive");
        if (password != null && !password.isEmpty())
            session.setPassword(password.getBytes(StandardCharsets.UTF_8));

        session.connect(CONNECT_TIMEOUT_MS);
        return session;

    }

    private static boolean isAuthFailure(JSchException e) {
        String message = e.getMessage() == null ? "" : e.getMessage().toLowerCase(Locale.ROOT);
        return message.contains("auth fail") || message.contains("auth cancel")
                || message.contains("too many authentication failures");
    }

    private static String describeType(String type) {
        return type == null ? "" : " (" + type + ")";
    }

    /**
     * Where OpenSSH keeps the host key of the given type, to print its
     * fingerprint with ssh-keygen.
     */
    private static String hostKeyFileHint(String type) {
        if (type == null)
            return "";
        String file = type.equals("ssh-ed25519") ? "ed25519" : type.startsWith("ecdsa-") ? "ecdsa"
                : type.startsWith("rsa-") || type.equals("ssh-rsa") ? "rsa" : null;
        return file == null ? "" : " (ssh-keygen -lf /etc/ssh/ssh_host_" + file + "_key.pub)";
    }

    private static String describe(Exception e, PinnedHostKeyRepository hostKeys) {

        String message = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
        String lower = message.toLowerCase(Locale.ROOT);

        if (hostKeys.isUntrusted() && hostKeys.hasAuthorities())
            return "The host presented the key " + hostKeys.getPresentedFingerprint()
                    + describeType(hostKeys.getPresentedType()) + ", not a host certificate signed by one of"
                    + " the platform's SSH CA keys. No credentials were sent. Give the host a certificate"
                    + " (HostCertificate in sshd_config), or check its key on the host"
                    + hostKeyFileHint(hostKeys.getPresentedType()) + " and paste it into the connection's"
                    + " \"Trusted SSH host key\" field.";
        if (lower.contains("rejected certificate") || lower.contains("rejected hostkey: "))
            return "The host's certificate is not trusted: " + message + ". No credentials were sent.";
        if (hostKeys.isUntrusted())
            return "The host key " + hostKeys.getPresentedFingerprint() + describeType(hostKeys.getPresentedType())
                    + " is not trusted yet. No credentials were sent. Check it on the host"
                    + hostKeyFileHint(hostKeys.getPresentedType()) + " and paste it into the connection's"
                    + " \"Trusted SSH host key\" field, or let the platform trust the key a host presents first.";
        if (lower.contains("hostkey has been changed") || lower.contains("reject hostkey"))
            return "The host key " + hostKeys.getPresentedFingerprint()
                    + " does not match the trusted one. No credentials were sent. If the host's key was"
                    + " changed on purpose, paste this fingerprint into the connection's \"Trusted SSH host"
                    + " key\" field.";
        if (e instanceof JSchException && isAuthFailure((JSchException) e))
            return "The target rejected the current credentials.";

        return "SSH error: " + message;

    }

    /**
     * Output received from the shell: the text seen since the last send (at
     * most its last {@link #MAX_STEP_OUTPUT} characters), which expectations
     * are matched against, plus a bounded transcript.
     */
    private static final class Output {

        private final StringBuilder step = new StringBuilder();
        private final Transcript transcript;
        private final byte[] buffer = new byte[4096];

        /**
         * Decodes across reads, so a character split between two is kept
         * whole.
         */
        private final CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPLACE).onUnmappableCharacter(CodingErrorAction.REPLACE);

        private final ByteBuffer pending = ByteBuffer.allocate(8192);

        private final CharBuffer decoded = CharBuffer.allocate(8192);

        Output(Map<String, String> values) {
            this.transcript = new Transcript(Arrays.asList(
                    values.get(SequenceScript.OLDPASS), values.get(SequenceScript.NEWPASS)));
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
                String text = decode(length);
                step.append(text);
                if (step.length() > MAX_STEP_OUTPUT)
                    step.delete(0, step.length() - MAX_STEP_OUTPUT);
                transcript.append(text);
                received = true;
            }
            return received;
        }

        /**
         * The text of the bytes read, the end of a character cut short kept
         * for the next read.
         */
        private String decode(int length) {
            pending.put(buffer, 0, length);
            pending.flip();
            decoded.clear();
            decoder.decode(pending, decoded, false);
            pending.compact();
            decoded.flip();
            return decoded.toString();
        }

        void startStep() {
            step.setLength(0);
        }

        boolean await(InputStream in, ChannelShell channel, Pattern pattern, long timeoutMs)
                throws IOException, InterruptedException {
            return awaitAny(in, channel, Arrays.asList(pattern), timeoutMs) == 0;
        }

        /**
         * Waits until the output since the last send matches one of the
         * given patterns, and returns the index of the one matching
         * earliest (the first given, if several match there), or -1 if
         * none did in time.
         */
        int awaitAny(InputStream in, ChannelShell channel, List<Pattern> patterns, long timeoutMs)
                throws IOException, InterruptedException {

            long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMs);
            boolean first = true;
            while (true) {

                // Matched again only when more output arrived
                if (pump(in) || first) {
                    first = false;
                    String seen = clean(step.toString());
                    int best = -1;
                    int bestStart = Integer.MAX_VALUE;
                    for (int i = 0; i < patterns.size(); i++) {
                        Matcher matcher = patterns.get(i).matcher(seen);
                        if (matcher.find() && matcher.start() < bestStart) {
                            best = i;
                            bestStart = matcher.start();
                        }
                    }
                    if (best >= 0)
                        return best;
                }

                if (channel.isClosed() && in.available() == 0)
                    return -1;
                if (System.nanoTime() - deadline >= 0)
                    return -1;
                Thread.sleep(POLL_INTERVAL_MS);
            }

        }

        /**
         * Waits for output to go quiet, so the final command has a chance to
         * finish before the shell is closed.
         */
        void settle(InputStream in, ChannelShell channel) throws IOException, InterruptedException {
            long end = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(SETTLE_MAX_MS);
            long lastOutput = System.nanoTime();
            while (end - System.nanoTime() > 0 && !channel.isClosed()) {
                if (pump(in))
                    lastOutput = System.nanoTime();
                else if (System.nanoTime() - lastOutput >= TimeUnit.MILLISECONDS.toNanos(SETTLE_QUIET_MS))
                    return;
                Thread.sleep(POLL_INTERVAL_MS);
            }
            // Closed by the shell: what it wrote last, for the transcript
            pump(in);
        }

        String transcript() {
            return transcript.render(Output::clean);
        }

        private static String clean(String text) {
            return ANSI_ESCAPE.matcher(text).replaceAll("").replace("\r", "");
        }

    }

}
