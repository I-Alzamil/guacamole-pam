package org.apache.guacamole.pam.winrm;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

/**
 * One WinRM (WS-Management) session with a host, logged in with NTLM as one
 * user, running commands in a remote shell. NTLM authenticates the
 * connection itself ({@link WinRmHttp}), so every request goes over the same
 * one, and the login is bound to the host's certificate.
 */
class WinRmSession implements AutoCloseable {

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

    private final WinRmTarget.Credentials user;
    private final String password;
    private final WinRmHttp http;
    private final String endpoint;
    private final NtlmLogin ntlm = new NtlmLogin();

    private boolean authenticated;

    WinRmSession(WinRmTarget target, WinRmTarget.Credentials user, String password) {
        this.user = user;
        this.password = password;
        this.http = new WinRmHttp(target.getHostname(), target.getPort(), target.getCertificate());
        this.endpoint = "https://" + target.getHostname() + ":" + target.getPort() + "/wsman";
    }

    /**
     * Fingerprint of the certificate the host presented, or null before
     * the TLS handshake.
     */
    String getPresentedCertificate() {
        return http.getPresentedCertificate();
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
        http.connect();
    }

    /**
     * Runs PowerShell with the given script, which reads its values (such as
     * passwords) from stdin, so they never appear on a command line.
     */
    Result runPowerShell(String script, String stdin) throws IOException {

        Document created = send(WsMan.ACTION_CREATE, null,
                WsMan.option("WINRS_NOPROFILE", "TRUE") + WsMan.option("WINRS_CODEPAGE", "65001"),
                "<rsp:Shell><rsp:InputStreams>stdin</rsp:InputStreams>"
                + "<rsp:OutputStreams>stdout stderr</rsp:OutputStreams></rsp:Shell>");
        String shellId = WsMan.text(created, "ShellId");
        if (shellId == null)
            throw new IOException("The host did not open a shell.");

        try {

            String encoded = Base64.getEncoder().encodeToString(script.getBytes(StandardCharsets.UTF_16LE));
            Document command = send(WsMan.SHELL + "Command", shellId,
                    WsMan.option("WINRS_CONSOLEMODE_STDIN", "TRUE") + WsMan.option("WINRS_SKIP_CMD_SHELL", "TRUE"),
                    "<rsp:CommandLine><rsp:Command>powershell.exe</rsp:Command><rsp:Arguments>-NoProfile"
                    + " -NonInteractive -EncodedCommand " + encoded + "</rsp:Arguments></rsp:CommandLine>");
            String commandId = WsMan.text(command, "CommandId");
            if (commandId == null)
                throw new IOException("The host did not start the command.");

            send(WsMan.SHELL + "Send", shellId, null,
                    "<rsp:Send><rsp:Stream Name=\"stdin\" CommandId=\"" + commandId + "\" End=\"true\">"
                    + Base64.getEncoder().encodeToString(stdin.getBytes(StandardCharsets.UTF_8))
                    + "</rsp:Stream></rsp:Send>");

            ByteArrayOutputStream stdout = new ByteArrayOutputStream();
            ByteArrayOutputStream stderr = new ByteArrayOutputStream();
            Integer exitCode = null;

            while (exitCode == null) {

                Document received = receive(shellId, commandId);
                if (received == null)
                    continue;

                NodeList streams = received.getElementsByTagNameNS(WsMan.NS_SHELL, "Stream");
                for (int i = 0; i < streams.getLength(); i++) {
                    Element stream = (Element) streams.item(i);
                    byte[] chunk = Base64.getDecoder().decode(stream.getTextContent().trim());
                    (("stdout".equals(stream.getAttribute("Name"))) ? stdout : stderr).write(chunk, 0, chunk.length);
                }

                NodeList states = received.getElementsByTagNameNS(WsMan.NS_SHELL, "CommandState");
                if (states.getLength() > 0 && ((Element) states.item(0)).getAttribute("State").endsWith("/Done")) {
                    String code = WsMan.text(received, "ExitCode");
                    exitCode = code == null ? 0 : Integer.parseInt(code);
                }

            }

            send(WsMan.SHELL + "Signal", shellId, null, "<rsp:Signal CommandId=\"" + commandId + "\">"
                    + "<rsp:Code>" + WsMan.SHELL + "signal/terminate</rsp:Code></rsp:Signal>");

            return new Result(exitCode, stdout.toString(StandardCharsets.UTF_8.name()).trim(),
                    WsMan.powerShellErrors(stderr.toString(StandardCharsets.UTF_8.name())));

        }
        finally {
            try {
                send(WsMan.ACTION_DELETE, shellId, null, "");
            }
            catch (IOException e) {
                // The shell times out on the host by itself
            }
        }

    }

    @Override
    public void close() {
        http.close();
    }

    /**
     * Sends a request, logging in first on a new connection.
     */
    private Document send(String action, String shellId, String options, String body) throws IOException {
        WinRmHttp.Response response = exchange(WsMan.envelope(endpoint, action, shellId, options, body));
        if (response.getStatus() != 200)
            throw new IOException("WinRM error (HTTP " + response.getStatus() + "): "
                    + WsMan.fault(response.getBody()));
        return WsMan.parse(response.getBody());
    }

    /**
     * Receives the output of a command, or returns null when the host only
     * reports that none came within the operation timeout.
     */
    private Document receive(String shellId, String commandId) throws IOException {
        WinRmHttp.Response response = exchange(WsMan.envelope(endpoint, WsMan.SHELL + "Receive", shellId, null,
                "<rsp:Receive><rsp:DesiredStream CommandId=\"" + commandId
                + "\">stdout stderr</rsp:DesiredStream></rsp:Receive>"));
        if (response.getStatus() == 500 && WsMan.isTimeoutFault(response.getBody()))
            return null;
        if (response.getStatus() != 200)
            throw new IOException("WinRM error (HTTP " + response.getStatus() + "): "
                    + WsMan.fault(response.getBody()));
        return WsMan.parse(response.getBody());
    }

    /**
     * Posts an envelope, with the NTLM login before the first one.
     */
    private WinRmHttp.Response exchange(String envelope) throws IOException {

        if (authenticated)
            return http.post(envelope, null);

        WinRmHttp.Response challenge = http.post("",
                "Negotiate " + Base64.getEncoder().encodeToString(ntlm.negotiate()));
        String token = null;
        for (String header : challenge.getHeaders("www-authenticate")) {
            if (header.regionMatches(true, 0, "Negotiate ", 0, 10))
                token = header.substring(10).trim();
        }
        if (challenge.getStatus() != 401 || token == null)
            throw new IOException("The host does not offer NTLM login over WinRM (HTTP " + challenge.getStatus()
                    + "). Check that Negotiate authentication is enabled.");

        byte[] answer;
        try {
            answer = ntlm.authenticate(Base64.getDecoder().decode(token), user, password, http.getCertificate());
        }
        catch (GeneralSecurityException | RuntimeException
                | com.hierynomus.protocol.commons.buffer.Buffer.BufferException e) {
            throw new IOException("Unable to answer the host's NTLM challenge: " + e.getMessage(), e);
        }

        WinRmHttp.Response response = http.post(envelope, "Negotiate " + Base64.getEncoder().encodeToString(answer));
        if (response.getStatus() == 401)
            throw new LoginRefusedException("The host refused the login of \"" + user.getName() + "\".");

        authenticated = true;
        return response;

    }

}
