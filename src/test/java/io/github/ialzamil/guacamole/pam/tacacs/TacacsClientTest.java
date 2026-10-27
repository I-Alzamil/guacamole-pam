package io.github.ialzamil.guacamole.pam.tacacs;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Test;

import io.github.ialzamil.guacamole.pam.management.PlatformTestResult;
import io.github.ialzamil.guacamole.pam.rotation.ChangeOutcome;

/**
 * The TACACS+ client against a scripted server answering as tac_plus-ng
 * does, for what a live server rarely shows: refusals, servers not allowing
 * changes, another shared secret, a backup server. The live suites test it
 * against tac_plus-ng itself.
 */
public class TacacsClientTest {

    private static final String SECRET = "TacacsSecr3t";

    private static final int PASS = 0x01, FAIL = 0x02, GETDATA = 0x03, GETPASS = 0x05, ERROR = 0x07;

    private final TacacsClient client = new TacacsClient();

    /**
     * The pad of RFC 8907, against the bytes tests/tacacs.py (Python's own
     * MD5) computes for the same packet.
     */
    @Test
    public void obfuscatesAsRfc8907() {
        byte[] body = new byte[40];
        for (int i = 0; i < body.length; i++)
            body[i] = (byte) i;
        byte[] expected = hex("ce561f0075bb6c6143fddf5fc2ec586ce04b19069e2c9b5a6e734ba18726318393dbd5355feaacb2");
        byte[] obfuscated = TacacsClient.obfuscate(body, 0x12345678, "pam-test-secret".getBytes(StandardCharsets.UTF_8),
                0xc0, 1);
        assertArrayEquals(expected, obfuscated);
        assertArrayEquals(body, TacacsClient.obfuscate(obfuscated, 0x12345678,
                "pam-test-secret".getBytes(StandardCharsets.UTF_8), 0xc0, 1));
    }

    @Test
    public void changesThePasswordAnsweringEachPrompt() throws Exception {
        try (FakeServer server = new FakeServer(SECRET, reply(GETDATA, "Old password: "),
                reply(GETPASS, "New password: "), reply(GETPASS, "Retype new password: "),
                reply(PASS, "Password change was successful."))) {
            ChangeOutcome outcome = client.changePassword(target(server, "Old-Pass1"), "New-Pass2");
            assertTrue(outcome.getError(), outcome.isCompleted());
            assertEquals(Arrays.asList("Old-Pass1", "New-Pass2", "New-Pass2"), server.answers);
            assertEquals(0x02, server.action);
            assertEquals("alice", server.username);
            assertFalse(outcome.getTranscript(),
                    outcome.getTranscript().contains("Pass1") || outcome.getTranscript().contains("Pass2"));
        }
    }

    /**
     * A PASS sent without the shared secret, as anyone on the way could
     * forge, is refused (RFC 8907, 4.5).
     */
    @Test
    public void refusesAnswersWithoutTheSharedSecret() throws Exception {
        try (FakeServer server = new FakeServer(SECRET, reply(PASS, ""))) {
            server.cleartext = true;
            ChangeOutcome outcome = client.changePassword(target(server, "Old-Pass1"), "New-Pass2");
            assertFalse(outcome.isCompleted());
            assertTrue(outcome.getError(), outcome.getError().contains("answered without the shared secret"));
        }
    }

    /**
     * A server passing the login before the new password was asked for
     * changed nothing.
     */
    @Test
    public void reportsAPassBeforeTheNewPassword() throws Exception {
        try (FakeServer server = new FakeServer(SECRET, reply(GETDATA, "Old password: "), reply(PASS, ""))) {
            ChangeOutcome outcome = client.changePassword(target(server, "Old-Pass1"), "New-Pass2");
            assertFalse(outcome.isCompleted());
            assertFalse(outcome.isNewPasswordSent());
        }
    }

    @Test
    public void reportsAServerNotAllowingChanges() throws Exception {
        try (FakeServer server = new FakeServer(SECRET,
                reply(ERROR, "Invalid or unsupported AUTHEN/START (action=2 authen_type=1)"))) {
            ChangeOutcome outcome = client.changePassword(target(server, "Old-Pass1"), "New-Pass2");
            assertFalse(outcome.isCompleted());
            assertFalse(outcome.isNewPasswordSent());
            assertTrue(outcome.getError(), outcome.getError().contains("does not support or allow password changes"));
            assertTrue(outcome.getError(), outcome.getError().contains("unsupported AUTHEN/START"));
        }
    }

    @Test
    public void reportsARefusal() throws Exception {
        try (FakeServer server = new FakeServer(SECRET, reply(GETDATA, "Old password: "),
                reply(GETPASS, "New password: "), reply(GETPASS, "Retype new password: "),
                reply(FAIL, "Permission denied."))) {
            ChangeOutcome outcome = client.changePassword(target(server, "Wrong-Pass"), "New-Pass2");
            assertFalse(outcome.isCompleted());
            assertTrue(outcome.isNewPasswordSent());
            assertTrue(outcome.getError(), outcome.getError().contains("refused the change: Permission denied."));
        }
    }

    @Test
    public void reportsAnotherSharedSecret() throws Exception {
        // tac_plus-ng closes the connection on a packet it cannot read
        try (FakeServer server = new FakeServer("another secret")) {
            ChangeOutcome outcome = client.changePassword(target(server, "Old-Pass1"), "New-Pass2");
            assertFalse(outcome.isNewPasswordSent());
            assertTrue(outcome.getError(), outcome.getError().contains("check the shared secret"));
        }
    }

    @Test
    public void refusesWithoutACurrentPassword() {
        ChangeOutcome outcome = client.changePassword(TacacsTarget.fromParameters(settings("127.0.0.1", 1, null)),
                "New-Pass2");
        assertFalse(outcome.isNewPasswordSent());
        assertTrue(outcome.getError(), outcome.getError().contains("no current password"));
    }

    @Test
    public void checksPasswordsByLoggingIn() throws Exception {
        try (FakeServer server = new FakeServer(SECRET, reply(GETPASS, "Password: "), reply(PASS, ""))) {
            assertTrue(client.acceptsPassword(target(server, null), "Right-Pass"));
            assertEquals(Collections.singletonList("Right-Pass"), server.answers);
            assertEquals(0x01, server.action);
        }
        try (FakeServer server = new FakeServer(SECRET, reply(GETPASS, "Password: "), reply(FAIL, "Password incorrect."))) {
            assertFalse(client.acceptsPassword(target(server, null), "Wrong-Pass"));
        }
    }

    @Test
    public void triesTheBackupServerWhenTheFirstIsUnreachable() throws Exception {
        // Both servers use the same port, on which only 127.0.0.1 listens
        try (FakeServer backup = new FakeServer(SECRET, reply(GETPASS, "Password: "), reply(PASS, ""))) {
            Map<String, String> settings = settings("127.0.0.2", backup.port, null);
            settings.put(TacacsTarget.BACKUP_SERVER, "127.0.0.1");
            assertTrue(client.acceptsPassword(TacacsTarget.fromParameters(settings), "Right-Pass"));
            assertEquals("alice", backup.username);
        }
        try (FakeServer other = new FakeServer(SECRET)) {
            assertTrue(client.changePassword(TacacsTarget.fromParameters(settings("127.0.0.2", other.port, "Old-Pass1")),
                    "New-Pass2").getError().contains("Unable to reach the TACACS+ server 127.0.0.2"));
        }
    }

    @Test
    public void testsWithoutSendingAPassword() throws Exception {
        try (FakeServer server = new FakeServer(SECRET, reply(GETPASS, "Password: "))) {
            PlatformTestResult result = client.test(target(server, null));
            assertTrue(result.isSuccess());
            assertTrue(result.getSteps().get(0).getText().contains("accepting the shared secret"));
            server.awaitClosed();
            assertEquals(Collections.singletonList(""), server.answers);
            assertTrue(server.aborted);
        }
        try (FakeServer server = new FakeServer("another secret")) {
            PlatformTestResult result = client.test(target(server, null));
            assertFalse(result.isSuccess());
            assertTrue(result.getSteps().get(0).getText().contains("check the shared secret"));
        }
    }

    private static TacacsTarget target(FakeServer server, String password) {
        return TacacsTarget.fromParameters(settings("127.0.0.1", server.port, password));
    }

    /**
     * A username's length is sent in one byte: 255 bytes of UTF-8 at most.
     */
    @Test
    public void refusesUsernamesTooLongToSend() {
        Map<String, String> settings = settings("127.0.0.1", 49, null);
        settings.put(TacacsTarget.USERNAME, String.join("", Collections.nCopies(255, "a")));
        assertEquals(255, TacacsTarget.fromParameters(settings).getUsername().length());
        settings.put(TacacsTarget.USERNAME, String.join("", Collections.nCopies(128, "\u00e9")));
        try {
            TacacsTarget.fromParameters(settings);
            fail("A username of 256 bytes is accepted.");
        }
        catch (IllegalArgumentException e) {
            assertEquals("The TACACS+ username is longer than TACACS+ allows (255 bytes).", e.getMessage());
        }
    }

    private static Map<String, String> settings(String host, int port, String password) {
        Map<String, String> settings = new HashMap<>();
        settings.put(TacacsTarget.SERVER, host);
        settings.put(TacacsTarget.PORT, Integer.toString(port));
        settings.put(TacacsTarget.SECRET, SECRET);
        settings.put(TacacsTarget.USERNAME, "alice");
        if (password != null)
            settings.put(TacacsTarget.PASSWORD, password);
        return settings;
    }

    private static int[] reply(int status, String message) {
        byte[] text = message.getBytes(StandardCharsets.UTF_8);
        int[] reply = new int[text.length + 1];
        reply[0] = status;
        for (int i = 0; i < text.length; i++)
            reply[i + 1] = text[i] & 0xff;
        return reply;
    }

    private static byte[] hex(String hex) {
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < bytes.length; i++)
            bytes[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        return bytes;
    }

    /**
     * Accepts one connection, reads the client's START, and answers with
     * each scripted reply in turn, reading the client's answer between them
     * (or, with another shared secret than the client's, closes the
     * connection on its first packet, as tac_plus-ng does).
     */
    private static final class FakeServer implements AutoCloseable {

        private final ServerSocket socket = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"));
        private final int port = socket.getLocalPort();
        private final byte[] key;
        private final List<int[]> replies;
        private final Thread thread;

        private volatile int action;
        private volatile String username;
        private volatile boolean aborted;

        /**
         * Whether replies are sent without the shared secret, flagged
         * unencrypted, as an attacker on the way could.
         */
        private volatile boolean cleartext;
        private final List<String> answers = Collections.synchronizedList(new ArrayList<String>());

        FakeServer(String secret, int[]... replies) throws IOException {
            this.key = secret.getBytes(StandardCharsets.UTF_8);
            this.replies = Arrays.asList(replies);
            this.thread = new Thread(this::serve);
            thread.setDaemon(true);
            thread.start();
        }

        private void serve() {
            try (Socket connection = socket.accept()) {

                DataInputStream in = new DataInputStream(connection.getInputStream());
                OutputStream out = connection.getOutputStream();

                byte[] start = readBody(in);
                if (!SECRET.equals(new String(key, StandardCharsets.UTF_8)))
                    return;
                action = start[0];
                username = new String(start, 8, start[4], StandardCharsets.UTF_8);

                for (int i = 0; i < replies.size(); i++) {
                    int[] reply = replies.get(i);
                    write(out, reply);
                    if (reply[0] == PASS || reply[0] == FAIL || reply[0] == ERROR)
                        return;
                    byte[] answer = readBody(in);
                    int length = ((answer[0] & 0xff) << 8) | (answer[1] & 0xff);
                    answers.add(new String(answer, 5, length, StandardCharsets.UTF_8));
                    aborted |= (answer[4] & 0x01) != 0;
                }

            }
            catch (IOException e) {
                // The client closed the connection
            }
        }

        private int sessionId;
        private int sequence;

        private byte[] readBody(DataInputStream in) throws IOException {
            byte[] header = new byte[12];
            in.readFully(header);
            ByteBuffer h = ByteBuffer.wrap(header);
            int version = h.get() & 0xff;
            h.get();
            sequence = h.get() & 0xff;
            h.get();
            sessionId = h.getInt();
            byte[] body = new byte[h.getInt()];
            in.readFully(body);
            return TacacsClient.obfuscate(body, sessionId, key, version, sequence);
        }

        private void write(OutputStream out, int[] reply) throws IOException {
            byte[] message = new byte[reply.length - 1];
            for (int i = 1; i < reply.length; i++)
                message[i - 1] = (byte) reply[i];
            ByteBuffer body = ByteBuffer.allocate(6 + message.length);
            body.put((byte) reply[0]).put((byte) 0).putShort((short) message.length).putShort((short) 0).put(message);
            sequence++;
            ByteBuffer packet = ByteBuffer.allocate(12 + body.capacity());
            packet.put((byte) 0xc0).put((byte) 0x01).put((byte) sequence).put((byte) (cleartext ? 0x01 : 0))
                .putInt(sessionId).putInt(body.capacity())
                .put(cleartext ? body.array() : TacacsClient.obfuscate(body.array(), sessionId, key, 0xc0, sequence));
            out.write(packet.array());
            out.flush();
        }

        void awaitClosed() throws InterruptedException {
            thread.join(5000);
        }

        @Override
        public void close() throws IOException {
            socket.close();
        }

    }

}
