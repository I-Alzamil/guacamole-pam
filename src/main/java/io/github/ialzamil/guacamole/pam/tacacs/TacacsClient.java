package io.github.ialzamil.guacamole.pam.tacacs;

import java.io.Closeable;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import io.github.ialzamil.guacamole.pam.management.PlatformTestResult;
import io.github.ialzamil.guacamole.pam.rotation.ChangeOutcome;

/**
 * TACACS+ client (RFC 8907) for changing and checking passwords of accounts
 * held by a TACACS+ server, over ASCII authentication: the only kind with a
 * password change dialogue. The server asks for what it needs (the
 * username, the old password, the new one, usually twice), and the client
 * answers each prompt in turn.
 *
 * A server changes a password only if it allows it, which it says only when
 * asked to change one: tac_plus-ng with a backend storing passwords does;
 * Facebook's tac_plus never does.
 */
public class TacacsClient {

    /**
     * How long to wait for a connection, and for each answer.
     */
    private static final int TIMEOUT_MS = 10000;

    /**
     * Most prompts answered in one dialogue: the username, the old password,
     * and the new one twice, with some to spare.
     */
    private static final int MAX_PROMPTS = 8;

    /**
     * Version 12.0, for ASCII authentication.
     */
    private static final int VERSION = 0xc0;

    private static final int TYPE_AUTHEN = 0x01;
    private static final int FLAG_UNENCRYPTED = 0x01;

    private static final int ACTION_LOGIN = 0x01;
    private static final int ACTION_CHPASS = 0x02;
    private static final int TYPE_ASCII = 0x01;
    private static final int SERVICE_LOGIN = 0x01;

    private static final int STATUS_PASS = 0x01;
    private static final int STATUS_FAIL = 0x02;
    private static final int STATUS_GETDATA = 0x03;
    private static final int STATUS_GETUSER = 0x04;
    private static final int STATUS_GETPASS = 0x05;
    private static final int STATUS_RESTART = 0x06;
    private static final int STATUS_ERROR = 0x07;
    private static final int STATUS_FOLLOW = 0x21;

    private static final int CONTINUE_ABORT = 0x01;

    /**
     * Port name sent with requests, which servers log.
     */
    private static final String PORT_NAME = "guacamole-pam";

    /**
     * Username of the dialogue started, then aborted, by a test.
     */
    private static final String TEST_USERNAME = "guacamole-pam-test";

    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * Changes the account's password from its current one, which the server
     * requires. Never throws.
     */
    public ChangeOutcome changePassword(TacacsTarget target, String newPassword) {

        if (target.getPassword() == null)
            return new ChangeOutcome(false, false, "The account has no current password: TACACS+ changes a"
                    + " password with the current one.", null, null);

        StringBuilder transcript = new StringBuilder();
        boolean sent = false;

        try (Session session = open(target)) {

            session.start(ACTION_CHPASS, target.getUsername());
            int secrets = 0;

            for (int prompt = 0; prompt <= MAX_PROMPTS; prompt++) {

                Reply reply = session.read();
                transcript.append("server: ").append(reply.describe()).append('\n');

                switch (reply.status) {

                    // Passing before the new password was sent changed nothing
                    case STATUS_PASS:
                        return sent ? new ChangeOutcome(true, true, null, transcript.toString(), null)
                                : new ChangeOutcome(false, false, "The TACACS+ server accepted the login before the"
                                        + " new password was asked for: it may not support password changes.",
                                        transcript.toString(), null);

                    case STATUS_FAIL:
                        return new ChangeOutcome(false, sent, "The TACACS+ server refused the change"
                                + reply.detail(), transcript.toString(), null);

                    case STATUS_ERROR:
                        return new ChangeOutcome(false, sent, (secrets == 0
                                ? "The TACACS+ server does not support or allow password changes"
                                : "The TACACS+ server reported an error") + reply.detail(),
                                transcript.toString(), null);

                    case STATUS_GETUSER:
                        session.answer(target.getUsername());
                        transcript.append("client: (username)\n");
                        break;

                    case STATUS_GETPASS:
                    case STATUS_GETDATA:
                        // The old password first, then the new one, as often as asked
                        if (secrets == 0) {
                            session.answer(target.getPassword());
                            transcript.append("client: (current password)\n");
                        }
                        else {
                            sent = true;
                            session.answer(newPassword);
                            transcript.append("client: (new password)\n");
                        }
                        secrets++;
                        break;

                    default:
                        return new ChangeOutcome(false, sent, "The TACACS+ server asked for something this"
                                + " extension does not support (" + reply.statusName() + ").",
                                transcript.toString(), null);

                }

            }

            return new ChangeOutcome(false, sent, "The TACACS+ server kept asking for more.", transcript.toString(),
                    null);

        }
        catch (IOException e) {
            return new ChangeOutcome(false, sent, describe(e), transcript.length() == 0 ? null : transcript.toString(),
                    null);
        }

    }

    /**
     * Returns whether the server accepts the given password of the account,
     * by logging in with it.
     *
     * @throws IOException
     *     If the server cannot be reached, or its answer cannot be read.
     */
    public boolean acceptsPassword(TacacsTarget target, String password) throws IOException {

        try (Session session = open(target)) {

            session.start(ACTION_LOGIN, target.getUsername());
            boolean answered = false;

            for (int prompt = 0; prompt <= MAX_PROMPTS; prompt++) {

                Reply reply = session.read();
                switch (reply.status) {

                    case STATUS_PASS:
                        return true;

                    case STATUS_FAIL:
                        return false;

                    case STATUS_GETUSER:
                        session.answer(target.getUsername());
                        break;

                    case STATUS_GETPASS:
                    case STATUS_GETDATA:
                        // Asked for more than the password, such as a new one
                        if (answered) {
                            session.abort();
                            return false;
                        }
                        session.answer(password == null ? "" : password);
                        answered = true;
                        break;

                    default:
                        throw new IOException(describe(reply));

                }

            }

            session.abort();
            return false;

        }

    }

    /**
     * Checks that each server answers, accepting the shared secret and this
     * Guacamole server as a client, by starting a login and abandoning it at
     * the first prompt: no password is sent or changed. Never throws.
     */
    public PlatformTestResult test(TacacsTarget target) {

        PlatformTestResult result = new PlatformTestResult();
        test(result, target, target.getServer());
        if (target.getBackupServer() != null)
            test(result, target, target.getBackupServer());

        if (result.isSuccess())
            result.info("Whether the server lets accounts change their password is only known when one is"
                    + " rotated: a TACACS+ server only says so when asked to change one.");
        return result;

    }

    private void test(PlatformTestResult result, TacacsTarget target, String server) {

        String name = server + ":" + target.getPort();
        try (Session session = new Session(server, target.getPort(), target.getSecret())) {
            session.start(ACTION_LOGIN, TEST_USERNAME);
            Reply reply = session.read();
            if (reply.status == STATUS_ERROR)
                result.failed("The TACACS+ server " + name + " reported an error" + reply.detail());
            else
                result.passed("The TACACS+ server " + name + " answers, accepting the shared secret and this"
                        + " Guacamole server as a client.");
            session.abort();
        }
        catch (IOException e) {
            result.failed(name + ": " + describe(e));
        }

    }

    /**
     * Connects to the first server, or to the backup server if the first
     * cannot be reached.
     */
    private static Session open(TacacsTarget target) throws IOException {
        try {
            return new Session(target.getServer(), target.getPort(), target.getSecret());
        }
        catch (Unreachable e) {
            if (target.getBackupServer() == null)
                throw e;
            return new Session(target.getBackupServer(), target.getPort(), target.getSecret());
        }
    }

    private static String describe(IOException e) {
        if (e instanceof Unreachable)
            return e.getMessage();
        if (e instanceof EOFException)
            return "The TACACS+ server closed the connection without answering: check the shared secret, and that"
                    + " the server accepts this Guacamole server as a client.";
        if (e instanceof SocketTimeoutException)
            return "The TACACS+ server did not answer within " + (TIMEOUT_MS / 1000) + " seconds.";
        if (e instanceof Unreadable)
            return e.getMessage();
        return "Unable to talk to the TACACS+ server: " + e.getMessage();
    }

    private static String describe(Reply reply) {
        return "The TACACS+ server answered " + reply.statusName() + reply.detail();
    }

    /**
     * Connecting to a server failed, so another may be tried.
     */
    private static final class Unreachable extends IOException {

        private static final long serialVersionUID = 1L;

        Unreachable(String message, Throwable cause) {
            super(message, cause);
        }

    }

    /**
     * The server's answer makes no sense, most likely as it obfuscated it
     * with another shared secret.
     */
    private static final class Unreadable extends IOException {

        private static final long serialVersionUID = 1L;

        Unreadable(String message) {
            super(message);
        }

    }

    /**
     * An answer of the server to a request or to a continuation.
     */
    private static final class Reply {

        private final int status;
        private final String message;

        Reply(int status, String message) {
            this.status = status;
            this.message = message;
        }

        String statusName() {
            switch (status) {
                case STATUS_PASS:    return "PASS";
                case STATUS_FAIL:    return "FAIL";
                case STATUS_GETDATA: return "GETDATA";
                case STATUS_GETUSER: return "GETUSER";
                case STATUS_GETPASS: return "GETPASS";
                case STATUS_RESTART: return "RESTART";
                case STATUS_ERROR:   return "ERROR";
                case STATUS_FOLLOW:  return "FOLLOW";
                default:             return "0x" + Integer.toHexString(status);
            }
        }

        /**
         * ": " and what the server said, or "." if nothing.
         */
        String detail() {
            return message.isEmpty() ? "." : ": " + message;
        }

        String describe() {
            return statusName() + (message.isEmpty() ? "" : " \"" + message + "\"");
        }

    }

    /**
     * One authentication session over its own connection.
     */
    private static final class Session implements Closeable {

        private final String server;
        private final Socket socket;
        private final DataInputStream in;
        private final OutputStream out;
        private final byte[] key;
        private final int sessionId = RANDOM.nextInt();
        private int sequence = 0;

        Session(String server, int port, String secret) throws IOException {
            this.server = server;
            this.key = secret.getBytes(StandardCharsets.UTF_8);
            Socket connected = new Socket();
            try {
                connected.connect(new InetSocketAddress(server, port), TIMEOUT_MS);
                connected.setSoTimeout(TIMEOUT_MS);
            }
            catch (IOException e) {
                connected.close();
                throw new Unreachable("Unable to reach the TACACS+ server " + server + ":" + port + ": "
                        + e.getMessage(), e);
            }
            this.socket = connected;
            this.in = new DataInputStream(socket.getInputStream());
            this.out = socket.getOutputStream();
        }

        /**
         * Sends the START of an ASCII authentication of the given action.
         */
        void start(int action, String username) throws IOException {
            byte[] user = username.getBytes(StandardCharsets.UTF_8);
            byte[] port = PORT_NAME.getBytes(StandardCharsets.UTF_8);
            ByteBuffer body = ByteBuffer.allocate(8 + user.length + port.length);
            body.put((byte) action).put((byte) 1).put((byte) TYPE_ASCII).put((byte) SERVICE_LOGIN)
                .put((byte) user.length).put((byte) port.length).put((byte) 0).put((byte) 0)
                .put(user).put(port);
            send(body.array());
        }

        /**
         * Answers the last prompt.
         */
        void answer(String text) throws IOException {
            send(continuation(text.getBytes(StandardCharsets.UTF_8), 0));
        }

        /**
         * Abandons the dialogue, telling the server so.
         */
        void abort() {
            try {
                send(continuation(new byte[0], CONTINUE_ABORT));
            }
            catch (IOException e) {
                // Closing ends it anyway
            }
        }

        private static byte[] continuation(byte[] message, int flags) {
            ByteBuffer body = ByteBuffer.allocate(5 + message.length);
            body.putShort((short) message.length).putShort((short) 0).put((byte) flags).put(message);
            return body.array();
        }

        private void send(byte[] body) throws IOException {
            sequence++;
            ByteBuffer packet = ByteBuffer.allocate(12 + body.length);
            packet.put((byte) VERSION).put((byte) TYPE_AUTHEN).put((byte) sequence).put((byte) 0)
                .putInt(sessionId).putInt(body.length).put(obfuscate(body, VERSION, sequence));
            out.write(packet.array());
            out.flush();
        }

        Reply read() throws IOException {

            byte[] header = new byte[12];
            in.readFully(header);
            ByteBuffer h = ByteBuffer.wrap(header);
            int version = h.get() & 0xff;
            int type = h.get() & 0xff;
            int seq = h.get() & 0xff;
            int flags = h.get() & 0xff;
            int id = h.getInt();
            int length = h.getInt();

            if ((version >> 4) != 0xc || type != TYPE_AUTHEN || seq != sequence + 1 || id != sessionId
                    || length < 6 || length > 65535)
                throw new Unreadable("The answer of the TACACS+ server " + server + " is not a TACACS+ answer"
                        + " to this request.");
            sequence = seq;

            byte[] body = new byte[length];
            in.readFully(body);
            // A shared secret is set: an answer without it could come from
            // anyone on the way (RFC 8907, 4.5)
            if ((flags & FLAG_UNENCRYPTED) != 0)
                throw new Unreadable("The TACACS+ server " + server + " answered without the shared secret, which"
                        + " is refused: configure the same secret on the server.");
            body = obfuscate(body, version, seq);

            ByteBuffer b = ByteBuffer.wrap(body);
            int status = b.get() & 0xff;
            b.get();
            int messageLength = b.getShort() & 0xffff;
            int dataLength = b.getShort() & 0xffff;
            if (6 + messageLength + dataLength != length)
                throw new Unreadable("The answer of the TACACS+ server " + server + " cannot be read: check the"
                        + " shared secret.");

            String message = new String(body, 6, messageLength, StandardCharsets.UTF_8).trim();
            return new Reply(status, message);

        }

        private byte[] obfuscate(byte[] body, int version, int seq) {
            return TacacsClient.obfuscate(body, sessionId, key, version, seq);
        }

        @Override
        public void close() throws IOException {
            socket.close();
        }

    }

    /**
     * XORs a packet body with the pseudo-random pad of RFC 8907 (section
     * 4.5), which obfuscates and restores it alike.
     */
    static byte[] obfuscate(byte[] body, int sessionId, byte[] key, int version, int seq) {
        try {
            MessageDigest md5 = MessageDigest.getInstance("MD5");
            byte[] result = new byte[body.length];
            byte[] previous = new byte[0];
            for (int offset = 0; offset < body.length; offset += 16) {
                md5.reset();
                md5.update(ByteBuffer.allocate(4).putInt(sessionId).array());
                md5.update(key);
                md5.update((byte) version);
                md5.update((byte) seq);
                md5.update(previous);
                previous = md5.digest();
                for (int i = 0; i < 16 && offset + i < body.length; i++)
                    result[offset + i] = (byte) (body[offset + i] ^ previous[i]);
            }
            return result;
        }
        catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("MD5 is unavailable.", e);
        }
    }

}
