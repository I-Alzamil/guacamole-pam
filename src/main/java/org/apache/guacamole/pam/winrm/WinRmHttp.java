package org.apache.guacamole.pam.winrm;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
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
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * One HTTPS connection to a WinRM host, kept open for every request: NTLM
 * authenticates the connection itself. Only what WinRM needs of HTTP/1.1 is
 * spoken: POST to /wsman, with a length or chunked responses.
 *
 * The host's certificate must match the pinned fingerprint; without one,
 * any certificate is accepted and its fingerprint is recorded, as SSH does
 * on first contact. Either way, the certificate is kept for the login's
 * channel binding.
 */
class WinRmHttp implements AutoCloseable {

    private static final int TIMEOUT_MS = 30000;

    private static final int MAX_RESPONSE_BYTES = 4 * 1024 * 1024;

    private static final int MAX_LINE_LENGTH = 16384;

    /**
     * A response: its status, headers (by lower case name) and body.
     */
    static final class Response {

        private int status;
        private final Map<String, List<String>> headers = new HashMap<>();
        private byte[] body;

        int getStatus() {
            return status;
        }

        List<String> getHeaders(String name) {
            return headers.getOrDefault(name.toLowerCase(Locale.ROOT), Collections.<String>emptyList());
        }

        byte[] getBody() {
            return body;
        }

    }

    private final String hostname;
    private final int port;
    private final CertificateCheck certificateCheck;

    private SSLSocket socket;
    private InputStream in;
    private OutputStream out;

    WinRmHttp(String hostname, int port, String pinnedCertificate) {
        this.hostname = hostname;
        this.port = port;
        this.certificateCheck = new CertificateCheck(pinnedCertificate);
    }

    /**
     * Fingerprint of the certificate the host presented, or null before
     * the TLS handshake.
     */
    String getPresentedCertificate() {
        return certificateCheck.presented;
    }

    /**
     * The trusted certificate, once the handshake accepted it.
     */
    X509Certificate getCertificate() {
        return certificateCheck.certificate;
    }

    /**
     * Opens the TLS connection, refusing a certificate other than the pinned
     * one before anything is sent.
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
            plain.connect(new InetSocketAddress(hostname, port), TIMEOUT_MS);
            socket = (SSLSocket) context.getSocketFactory().createSocket(plain, hostname, port, true);
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
     * Posts a SOAP envelope to /wsman, and reads the response.
     *
     * @param authorization
     *     The Authorization header, or null.
     */
    Response post(String body, String authorization) throws IOException {

        byte[] data = body.getBytes(StandardCharsets.UTF_8);
        StringBuilder request = new StringBuilder()
            .append("POST /wsman HTTP/1.1\r\n")
            .append("Host: ").append(hostname).append(':').append(port).append("\r\n")
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

        List<String> encoding = response.getHeaders("transfer-encoding");
        if (!encoding.isEmpty() && encoding.get(0).equalsIgnoreCase("chunked")) {
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
            List<String> length = response.getHeaders("content-length");
            response.body = readBytes(length.isEmpty() ? 0 : Integer.parseInt(length.get(0)), 0);
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
            if (line.length() > MAX_LINE_LENGTH)
                throw new IOException("Header line too long.");
        }
        return line.toString();
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
