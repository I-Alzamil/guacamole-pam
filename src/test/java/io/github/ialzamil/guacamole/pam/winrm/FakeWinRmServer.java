package io.github.ialzamil.guacamole.pam.winrm;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;

/**
 * A WinRM HTTPS endpoint answering like Windows, for tests: the NTLM
 * challenge recorded from Windows 11, then a remote shell running one
 * command whose output is set by the test. It records what the client sent.
 * Its first Receive answers that no output came yet, and output comes
 * chunked, as Windows may do.
 */
final class FakeWinRmServer implements AutoCloseable {

    private static final String SHELL = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell";

    private static final Pattern ACTION = Pattern.compile("<a:Action[^>]*>([^<]*)</a:Action>");
    private static final Pattern STDIN = Pattern.compile("<rsp:Stream Name=\"stdin\"[^>]*>([^<]*)</rsp:Stream>");
    private static final Pattern ARGUMENTS = Pattern.compile("<rsp:Arguments>([^<]*)</rsp:Arguments>");

    // What the command answers
    volatile String stdout = "PAM-OK\r\n";
    volatile String stderr = "";
    volatile int exitCode = 0;
    volatile boolean refuseLogin = false;
    volatile boolean refuseShell = false;

    // What the client sent
    final List<String> actions = Collections.synchronizedList(new ArrayList<>());
    final List<String> commandLines = Collections.synchronizedList(new ArrayList<>());
    final StringBuilder stdin = new StringBuilder();
    volatile int requests = 0;
    volatile int ntlmMessages = 0;

    private final SSLServerSocket server;
    private final String challenge;
    private final Thread thread;

    FakeWinRmServer() throws Exception {
        this("test-server.p12");
    }

    /**
     * A server presenting the certificate (and its chain) of the given
     * PKCS12 resource, whose password is "changeit".
     */
    FakeWinRmServer(String keyStore) throws Exception {

        KeyStore store = KeyStore.getInstance("PKCS12");
        try (InputStream in = getClass().getResourceAsStream(keyStore)) {
            store.load(in, "changeit".toCharArray());
        }
        KeyManagerFactory keys = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keys.init(store, "changeit".toCharArray());
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(keys.getKeyManagers(), null, null);

        try (InputStream in = getClass().getResourceAsStream("challenge-windows11.b64")) {
            challenge = new String(in.readAllBytes(), StandardCharsets.US_ASCII).trim();
        }

        server = (SSLServerSocket) context.getServerSocketFactory().createServerSocket(0, 5,
                InetAddress.getLoopbackAddress());
        thread = new Thread(this::serve, "fake-winrm");
        thread.setDaemon(true);
        thread.start();

    }

    int getPort() {
        return server.getLocalPort();
    }

    private void serve() {
        while (!server.isClosed()) {
            try (Socket socket = server.accept()) {
                // Each response is sent whole when flushed, as Windows does
                handle(new BufferedInputStream(socket.getInputStream()),
                        new BufferedOutputStream(socket.getOutputStream()));
            }
            catch (IOException e) {
                // Connection closed, or a client refusing the certificate
            }
        }
    }

    private void handle(InputStream in, OutputStream out) throws IOException {

        boolean authenticated = false;
        int receives = 0;

        while (true) {

            String requestLine = line(in);
            if (requestLine == null)
                return;

            String authorization = null;
            int length = 0;
            for (String header; !(header = line(in)).isEmpty(); ) {
                String lower = header.toLowerCase(Locale.ROOT);
                if (lower.startsWith("authorization:"))
                    authorization = header.substring(14).trim();
                else if (lower.startsWith("content-length:"))
                    length = Integer.parseInt(header.substring(15).trim());
            }
            String body = new String(in.readNBytes(length), StandardCharsets.UTF_8);
            requests++;

            if (!authenticated) {
                if (authorization == null || !authorization.startsWith("Negotiate ")) {
                    respond(out, 401, "WWW-Authenticate: Negotiate\r\n", "", false);
                    continue;
                }
                byte[] token = Base64.getDecoder().decode(authorization.substring(10));
                ntlmMessages++;
                if (token[8] == 1) {
                    respond(out, 401, "WWW-Authenticate: Negotiate " + challenge + "\r\n", "", false);
                    continue;
                }
                if (refuseLogin) {
                    respond(out, 401, "", "", false);
                    continue;
                }
                authenticated = true;
            }

            Matcher action = ACTION.matcher(body);
            String name = action.find() ? action.group(1).replaceAll(".*/", "") : "";
            actions.add(name);

            switch (name) {

                case "Create":
                    // As Windows answers accounts its RootSDDL leaves out
                    if (refuseShell) {
                        respond(out, 500, "", envelope("<s:Fault><s:Code><s:Value>s:Sender</s:Value></s:Code>"
                                + "<s:Detail><f:WSManFault xmlns:f=\"http://schemas.microsoft.com/wbem/wsman/1/wsmanfault\""
                                + " Code=\"5\"><f:Message>Access is denied. </f:Message></f:WSManFault></s:Detail>"
                                + "</s:Fault>"), false);
                        break;
                    }
                    respond(out, 200, "", envelope("<rsp:Shell><rsp:ShellId>SHELL-1</rsp:ShellId></rsp:Shell>"), false);
                    break;

                case "Command":
                    Matcher arguments = ARGUMENTS.matcher(body);
                    commandLines.add(arguments.find() ? arguments.group(1) : "");
                    respond(out, 200, "", envelope("<rsp:CommandResponse><rsp:CommandId>CMD-1</rsp:CommandId>"
                            + "</rsp:CommandResponse>"), false);
                    break;

                case "Send":
                    Matcher stream = STDIN.matcher(body);
                    if (stream.find())
                        synchronized (stdin) {
                            stdin.append(new String(Base64.getDecoder().decode(stream.group(1)), StandardCharsets.UTF_8));
                        }
                    respond(out, 200, "", envelope("<rsp:SendResponse/>"), false);
                    break;

                case "Receive":
                    receives++;
                    if (receives == 1) {
                        // Nothing yet within the operation timeout
                        respond(out, 500, "", envelope("<s:Fault><s:Code><s:Value>s:Receiver</s:Value></s:Code>"
                                + "<s:Detail><f:WSManFault xmlns:f=\"http://schemas.microsoft.com/wbem/wsman/1/wsmanfault\""
                                + " Code=\"2150858793\"><f:Message>The WS-Management service cannot complete the operation"
                                + " within the time specified in OperationTimeout.</f:Message></f:WSManFault></s:Detail>"
                                + "</s:Fault>"), false);
                    }
                    else {
                        respond(out, 200, "", envelope("<rsp:ReceiveResponse>"
                                + streamOf("stdout", stdout) + streamOf("stderr", stderr)
                                + "<rsp:CommandState CommandId=\"CMD-1\" State=\"" + SHELL + "/CommandState/Done\">"
                                + "<rsp:ExitCode>" + exitCode + "</rsp:ExitCode></rsp:CommandState>"
                                + "</rsp:ReceiveResponse>"), true);
                    }
                    break;

                default:
                    respond(out, 200, "", envelope(""), false);

            }

        }

    }

    private static String streamOf(String name, String text) {
        return text.isEmpty() ? "" : "<rsp:Stream Name=\"" + name + "\" CommandId=\"CMD-1\">"
                + Base64.getEncoder().encodeToString(text.getBytes(StandardCharsets.UTF_8)) + "</rsp:Stream>";
    }

    private static String envelope(String body) {
        return "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:rsp=\"" + SHELL + "\">"
                + "<s:Header/><s:Body>" + body + "</s:Body></s:Envelope>";
    }

    private static void respond(OutputStream out, int status, String headers, String body, boolean chunked)
            throws IOException {

        byte[] data = body.getBytes(StandardCharsets.UTF_8);
        StringBuilder response = new StringBuilder("HTTP/1.1 ").append(status).append(status == 200 ? " OK" : "")
                .append("\r\n").append(headers).append("Content-Type: application/soap+xml;charset=UTF-8\r\n");

        if (!chunked) {
            response.append("Content-Length: ").append(data.length).append("\r\n\r\n");
            out.write(response.toString().getBytes(StandardCharsets.ISO_8859_1));
            out.write(data);
        }
        else {
            response.append("Transfer-Encoding: chunked\r\n\r\n");
            out.write(response.toString().getBytes(StandardCharsets.ISO_8859_1));
            ByteArrayOutputStream chunks = new ByteArrayOutputStream();
            for (int offset = 0; offset < data.length; offset += 100) {
                int size = Math.min(100, data.length - offset);
                chunks.write((Integer.toHexString(size) + "\r\n").getBytes(StandardCharsets.ISO_8859_1));
                chunks.write(data, offset, size);
                chunks.write("\r\n".getBytes(StandardCharsets.ISO_8859_1));
            }
            chunks.write("0\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1));
            out.write(chunks.toByteArray());
        }

        out.flush();

    }

    private static String line(InputStream in) throws IOException {
        StringBuilder line = new StringBuilder();
        for (int c; (c = in.read()) != '\n'; ) {
            if (c < 0)
                return line.length() == 0 ? null : line.toString();
            if (c != '\r')
                line.append((char) c);
        }
        return line.toString();
    }

    @Override
    public void close() throws IOException {
        server.close();
    }

}
