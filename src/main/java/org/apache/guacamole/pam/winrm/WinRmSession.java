package org.apache.guacamole.pam.winrm;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

/**
 * One WinRM (WS-Management) connection over HTTPS to a host, logged in with
 * NTLM as one user, running commands in a remote shell. NTLM authenticates
 * the connection itself, so every request goes over the same socket.
 *
 * The host's certificate must match the pinned fingerprint; without one,
 * any certificate is accepted and its fingerprint is recorded, as SSH does
 * on first contact. Either way the login is bound to that certificate.
 */
class WinRmSession implements AutoCloseable {

    private static final int TIMEOUT_MS = 30000;

    private static final int MAX_RESPONSE_BYTES = 4 * 1024 * 1024;

    private static final String NS_SOAP = "http://www.w3.org/2003/05/soap-envelope";
    private static final String NS_SHELL = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell";
    private static final String NS_FAULT = "http://schemas.microsoft.com/wbem/wsman/1/wsmanfault";

    private static final String ACTION_CREATE = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create";
    private static final String ACTION_DELETE = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete";
    private static final String SHELL = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/";

    /**
     * Error PowerShell writes, in its CLIXML form, to stderr.
     */
    private static final Pattern CLIXML_ERROR = Pattern.compile("<S S=\"Error\">(.*?)</S>", Pattern.DOTALL);
    private static final Pattern CLIXML_ESCAPE = Pattern.compile("_x([0-9A-Fa-f]{4})_");

    /**
     * The output of a command.
     */
    static final class Result {

        private final int exitCode;
        private final String output;
        private final String error;

        Result(int exitCode, String output, String error) {
            this.exitCode = exitCode;
            this.output = output;
            this.error = error;
        }

        int getExitCode() {
            return exitCode;
        }

        String getOutput() {
            return output;
        }

        /**
         * PowerShell's error messages, as text.
         */
        String getError() {
            return error;
        }

    }

    /**
     * Raised when the host refuses the user's credentials.
     */
    static final class LoginRefusedException extends IOException {
        LoginRefusedException(String message) {
            super(message);
        }
    }

    private final WinRmTarget target;
    private final WinRmTarget.Credentials user;
    private final String password;
    private final CertificateCheck certificateCheck;
    private final NtlmLogin ntlm = new NtlmLogin();

    private SSLSocket socket;
    private InputStream in;
    private OutputStream out;
    private boolean authenticated;

    WinRmSession(WinRmTarget target, WinRmTarget.Credentials user, String password) {
        this.target = target;
        this.user = user;
        this.password = password;
        this.certificateCheck = new CertificateCheck(target.getCertificate());
    }

    /**
     * Fingerprint of the certificate the host presented, or null before
     * the TLS handshake.
     */
    String getPresentedCertificate() {
        return certificateCheck.presented;
    }

    /**
     * Whether the host accepted the login, after which commands may have run.
     */
    boolean isLoggedIn() {
        return authenticated;
    }

    /**
     * Opens the TLS connection. No credentials are sent unless the
     * certificate is the trusted one.
     */
    void connect() throws IOException {

        try {
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, new TrustManager[] { certificateCheck }, new SecureRandom());

            // Requests are written whole, then flushed: never hold back their
            // last packet until the host acknowledges the first, which a
            // host delaying acknowledgements (Windows: up to 200 ms) would
            // turn into a wait on every request
            Socket plain = new Socket();
            plain.setTcpNoDelay(true);
            plain.connect(new InetSocketAddress(target.getHostname(), target.getPort()), TIMEOUT_MS);
            socket = (SSLSocket) context.getSocketFactory().createSocket(plain, target.getHostname(),
                    target.getPort(), true);
            socket.setSoTimeout(TIMEOUT_MS);
            socket.startHandshake();
        }
        catch (GeneralSecurityException e) {
            throw new IOException("Unable to set up TLS: " + e.getMessage(), e);
        }

        in = new BufferedInputStream(socket.getInputStream());
        out = new BufferedOutputStream(socket.getOutputStream());

    }

    /**
     * Runs PowerShell with the given script, which reads its values (such as
     * passwords) from stdin, so they never appear on a command line.
     */
    Result runPowerShell(String script, String stdin) throws IOException {

        Document created = send(envelope(ACTION_CREATE, null,
                option("WINRS_NOPROFILE", "TRUE") + option("WINRS_CODEPAGE", "65001"),
                "<rsp:Shell><rsp:InputStreams>stdin</rsp:InputStreams>"
                + "<rsp:OutputStreams>stdout stderr</rsp:OutputStreams></rsp:Shell>"));
        String shellId = text(created, "ShellId");
        if (shellId == null)
            throw new IOException("The host did not open a shell.");

        try {

            String encoded = Base64.getEncoder().encodeToString(script.getBytes(StandardCharsets.UTF_16LE));
            Document command = send(envelope(SHELL + "Command", shellId,
                    option("WINRS_CONSOLEMODE_STDIN", "TRUE") + option("WINRS_SKIP_CMD_SHELL", "TRUE"),
                    "<rsp:CommandLine><rsp:Command>powershell.exe</rsp:Command><rsp:Arguments>-NoProfile"
                    + " -NonInteractive -EncodedCommand " + encoded + "</rsp:Arguments></rsp:CommandLine>"));
            String commandId = text(command, "CommandId");
            if (commandId == null)
                throw new IOException("The host did not start the command.");

            send(envelope(SHELL + "Send", shellId, null,
                    "<rsp:Send><rsp:Stream Name=\"stdin\" CommandId=\"" + commandId + "\" End=\"true\">"
                    + Base64.getEncoder().encodeToString(stdin.getBytes(StandardCharsets.UTF_8))
                    + "</rsp:Stream></rsp:Send>"));

            ByteArrayOutputStream stdout = new ByteArrayOutputStream();
            ByteArrayOutputStream stderr = new ByteArrayOutputStream();
            Integer exitCode = null;

            while (exitCode == null) {

                Document received = sendAllowingTimeout(envelope(SHELL + "Receive", shellId, null,
                        "<rsp:Receive><rsp:DesiredStream CommandId=\"" + commandId
                        + "\">stdout stderr</rsp:DesiredStream></rsp:Receive>"));
                if (received == null)
                    continue;

                NodeList streams = received.getElementsByTagNameNS(NS_SHELL, "Stream");
                for (int i = 0; i < streams.getLength(); i++) {
                    Element stream = (Element) streams.item(i);
                    byte[] chunk = Base64.getDecoder().decode(stream.getTextContent().trim());
                    (("stdout".equals(stream.getAttribute("Name"))) ? stdout : stderr).write(chunk, 0, chunk.length);
                }

                NodeList states = received.getElementsByTagNameNS(NS_SHELL, "CommandState");
                if (states.getLength() > 0 && ((Element) states.item(0)).getAttribute("State").endsWith("/Done")) {
                    String code = text(received, "ExitCode");
                    exitCode = code == null ? 0 : Integer.parseInt(code);
                }

            }

            send(envelope(SHELL + "Signal", shellId, null, "<rsp:Signal CommandId=\"" + commandId + "\">"
                    + "<rsp:Code>" + SHELL + "signal/terminate</rsp:Code></rsp:Signal>"));

            return new Result(exitCode, stdout.toString(StandardCharsets.UTF_8.name()).trim(),
                    powerShellErrors(stderr.toString(StandardCharsets.UTF_8.name())));

        }
        finally {
            try {
                send(envelope(ACTION_DELETE, shellId, null, ""));
            }
            catch (IOException e) {
                // The shell times out on the host by itself
            }
        }

    }

    @Override
    public void close() {
        if (socket != null) {
            try {
                socket.close();
            }
            catch (IOException e) {
                // Nothing to do
            }
        }
    }

    // ---- WS-Management ----

    private String envelope(String action, String shellId, String options, String body) {
        return "<s:Envelope xmlns:s=\"" + NS_SOAP + "\""
            + " xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\""
            + " xmlns:w=\"http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd\" xmlns:rsp=\"" + NS_SHELL + "\">"
            + "<s:Header>"
            + "<a:To>https://" + escape(target.getHostname()) + ":" + target.getPort() + "/wsman</a:To>"
            + "<w:ResourceURI s:mustUnderstand=\"true\">" + SHELL + "cmd</w:ResourceURI>"
            + "<a:ReplyTo><a:Address s:mustUnderstand=\"true\">"
            + "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo>"
            + "<a:Action s:mustUnderstand=\"true\">" + action + "</a:Action>"
            + "<w:MaxEnvelopeSize s:mustUnderstand=\"true\">153600</w:MaxEnvelopeSize>"
            + "<a:MessageID>uuid:" + UUID.randomUUID() + "</a:MessageID>"
            + "<w:Locale xml:lang=\"en-US\" s:mustUnderstand=\"false\"/>"
            + "<w:OperationTimeout>PT20S</w:OperationTimeout>"
            + (shellId == null ? "" : "<w:SelectorSet><w:Selector Name=\"ShellId\">" + escape(shellId)
                    + "</w:Selector></w:SelectorSet>")
            + (options == null ? "" : "<w:OptionSet>" + options + "</w:OptionSet>")
            + "</s:Header><s:Body>" + body + "</s:Body></s:Envelope>";
    }

    private static String option(String name, String value) {
        return "<w:Option Name=\"" + name + "\">" + value + "</w:Option>";
    }

    /**
     * Sends a request, logging in first on a new connection.
     */
    private Document send(String envelope) throws IOException {
        Response response = exchange(envelope);
        if (response.status != 200)
            throw new IOException("WinRM error (HTTP " + response.status + "): " + fault(response.body));
        return parse(response.body);
    }

    /**
     * Like {@link #send}, but returns null when the host only reports that
     * no output came within the operation timeout.
     */
    private Document sendAllowingTimeout(String envelope) throws IOException {
        Response response = exchange(envelope);
        if (response.status == 500 && isTimeoutFault(response.body))
            return null;
        if (response.status != 200)
            throw new IOException("WinRM error (HTTP " + response.status + "): " + fault(response.body));
        return parse(response.body);
    }

    private Response exchange(String envelope) throws IOException {

        if (authenticated)
            return post(envelope, null);

        Response challenge = post("", "Negotiate " + Base64.getEncoder().encodeToString(ntlm.negotiate()));
        String token = null;
        for (String header : challenge.headers.getOrDefault("www-authenticate", new ArrayList<>())) {
            if (header.regionMatches(true, 0, "Negotiate ", 0, 10))
                token = header.substring(10).trim();
        }
        if (challenge.status != 401 || token == null)
            throw new IOException("The host does not offer NTLM login over WinRM (HTTP " + challenge.status
                    + "). Check that Negotiate authentication is enabled.");

        byte[] answer;
        try {
            answer = ntlm.authenticate(Base64.getDecoder().decode(token), user, password,
                    certificateCheck.certificate);
        }
        catch (GeneralSecurityException | RuntimeException
                | com.hierynomus.protocol.commons.buffer.Buffer.BufferException e) {
            throw new IOException("Unable to answer the host's NTLM challenge: " + e.getMessage(), e);
        }

        Response response = post(envelope, "Negotiate " + Base64.getEncoder().encodeToString(answer));
        if (response.status == 401)
            throw new LoginRefusedException("The host refused the login of \"" + user.getName() + "\".");

        authenticated = true;
        return response;

    }

    // ---- HTTP/1.1 ----

    private static final class Response {
        private int status;
        private final Map<String, List<String>> headers = new HashMap<>();
        private byte[] body;
    }

    private Response post(String body, String authorization) throws IOException {

        byte[] data = body.getBytes(StandardCharsets.UTF_8);
        StringBuilder request = new StringBuilder()
            .append("POST /wsman HTTP/1.1\r\n")
            .append("Host: ").append(target.getHostname()).append(':').append(target.getPort()).append("\r\n")
            .append("Content-Type: application/soap+xml;charset=UTF-8\r\n")
            .append("Connection: Keep-Alive\r\n");
        if (authorization != null)
            request.append("Authorization: ").append(authorization).append("\r\n");
        request.append("Content-Length: ").append(data.length).append("\r\n\r\n");

        out.write(request.toString().getBytes(StandardCharsets.ISO_8859_1));
        out.write(data);
        out.flush();

        Response response = new Response();
        String[] status = readLine().split(" ", 3);
        if (status.length < 2 || !status[0].startsWith("HTTP/"))
            throw new IOException("Not an HTTP response.");
        response.status = Integer.parseInt(status[1]);

        for (String header; !(header = readLine()).isEmpty(); ) {
            int colon = header.indexOf(':');
            if (colon > 0)
                response.headers.computeIfAbsent(header.substring(0, colon).trim().toLowerCase(Locale.ROOT),
                        name -> new ArrayList<>()).add(header.substring(colon + 1).trim());
        }

        List<String> encoding = response.headers.get("transfer-encoding");
        if (encoding != null && encoding.get(0).equalsIgnoreCase("chunked")) {
            ByteArrayOutputStream content = new ByteArrayOutputStream();
            for (int size; (size = Integer.parseInt(readLine().split(";")[0].trim(), 16)) > 0; ) {
                content.write(readBytes(size, content.size()));
                readLine();
            }
            while (!readLine().isEmpty()) {
                // Trailers
            }
            response.body = content.toByteArray();
        }
        else {
            List<String> length = response.headers.get("content-length");
            response.body = readBytes(length == null ? 0 : Integer.parseInt(length.get(0)), 0);
        }

        return response;

    }

    private byte[] readBytes(int count, int alreadyRead) throws IOException {
        if (count < 0 || count + alreadyRead > MAX_RESPONSE_BYTES)
            throw new IOException("Response too large.");
        byte[] data = new byte[count];
        int offset = 0;
        while (offset < count) {
            int read = in.read(data, offset, count - offset);
            if (read < 0)
                throw new EOFException("The host closed the connection.");
            offset += read;
        }
        return data;
    }

    private String readLine() throws IOException {
        StringBuilder line = new StringBuilder();
        for (int c; (c = in.read()) != '\n'; ) {
            if (c < 0)
                throw new EOFException("The host closed the connection.");
            if (c != '\r')
                line.append((char) c);
            if (line.length() > 16384)
                throw new IOException("Header line too long.");
        }
        return line.toString();
    }

    // ---- XML ----

    private static Document parse(byte[] xml) throws IOException {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setExpandEntityReferences(false);
            return factory.newDocumentBuilder().parse(new ByteArrayInputStream(xml));
        }
        catch (ParserConfigurationException | SAXException e) {
            throw new IOException("Invalid WinRM response: " + e.getMessage(), e);
        }
    }

    private static String text(Document document, String name) {
        NodeList nodes = document.getElementsByTagNameNS(NS_SHELL, name);
        return nodes.getLength() == 0 ? null : nodes.item(0).getTextContent().trim();
    }

    private static boolean isTimeoutFault(byte[] body) {
        try {
            NodeList faults = parse(body).getElementsByTagNameNS(NS_FAULT, "WSManFault");
            return faults.getLength() > 0 && "2150858793".equals(((Element) faults.item(0)).getAttribute("Code"));
        }
        catch (IOException e) {
            return false;
        }
    }

    private static String fault(byte[] body) {
        try {
            Document document = parse(body);
            NodeList messages = document.getElementsByTagNameNS(NS_FAULT, "Message");
            if (messages.getLength() > 0)
                return messages.item(0).getTextContent().trim();
            NodeList texts = document.getElementsByTagNameNS(NS_SOAP, "Text");
            if (texts.getLength() > 0)
                return texts.item(0).getTextContent().trim();
        }
        catch (IOException e) {
            // Not XML
        }
        String text = new String(body, StandardCharsets.UTF_8).trim();
        return text.isEmpty() ? "no details" : text.substring(0, Math.min(text.length(), 300));
    }

    /**
     * The error messages in PowerShell's CLIXML stderr, as plain text.
     */
    static String powerShellErrors(String stderr) {
        StringBuilder errors = new StringBuilder();
        Matcher matcher = CLIXML_ERROR.matcher(stderr);
        while (matcher.find()) {
            Matcher escape = CLIXML_ESCAPE.matcher(matcher.group(1));
            StringBuffer text = new StringBuffer();
            while (escape.find())
                escape.appendReplacement(text, Matcher.quoteReplacement(
                        String.valueOf((char) Integer.parseInt(escape.group(1), 16))));
            escape.appendTail(text);
            errors.append(text.toString().replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&"));
        }
        String result = errors.toString().replaceAll("\\s+", " ").trim();
        return result.isEmpty() ? (stderr.contains("CLIXML") ? "" : stderr.trim()) : result;
    }

    private static String escape(String value) {
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }

    /**
     * Requires the pinned certificate, or records the one presented when
     * none is pinned, and keeps it for the channel binding.
     */
    private static final class CertificateCheck implements X509TrustManager {

        private final String pinned;
        private volatile String presented;
        private volatile X509Certificate certificate;

        CertificateCheck(String pinned) {
            this.pinned = pinned;
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            if (chain == null || chain.length == 0)
                throw new CertificateException("The host presented no certificate.");
            presented = fingerprint(chain[0]);
            if (pinned != null && !pinned.equals(presented))
                throw new CertificateException("The host's certificate " + presented
                        + " does not match the trusted fingerprint " + pinned + ". No credentials were sent.");
            certificate = chain[0];
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            throw new CertificateException("Not a server.");
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }

        private static String fingerprint(X509Certificate certificate) throws CertificateException {
            try {
                byte[] digest = MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded());
                StringBuilder hex = new StringBuilder();
                for (byte b : digest) {
                    if (hex.length() > 0)
                        hex.append(':');
                    hex.append(String.format("%02X", b));
                }
                return hex.toString();
            }
            catch (NoSuchAlgorithmException e) {
                throw new CertificateException(e);
            }
        }

    }

}
