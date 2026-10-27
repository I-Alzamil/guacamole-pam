package io.github.ialzamil.guacamole.pam.notification.syslog;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Objects;

import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;

import org.apache.guacamole.GuacamoleClientException;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleServerException;

import io.github.ialzamil.guacamole.pam.Certificates;
import io.github.ialzamil.guacamole.pam.notification.Event;
import io.github.ialzamil.guacamole.pam.notification.EventType;
import io.github.ialzamil.guacamole.pam.notification.Notifier;
import io.github.ialzamil.guacamole.pam.settings.PamSettings;

/**
 * Sends events to a syslog server, as {@link SyslogFormat} writes them:
 * over TLS (RFC 5425), checking the server's certificate and name, over TCP
 * (RFC 6587, octet counting, as RFC 5425 frames them too), or over UDP (RFC
 * 5426), which never says whether a message arrived. A TCP or TLS
 * connection is kept open between events, and opened again once the
 * settings change, or the server closed it.
 */
public final class SyslogNotifier implements Notifier {

    private static final int CONNECT_TIMEOUT_MS = 5000;

    private static final int WRITE_TIMEOUT_MS = 10000;

    private final PamSettings settings;

    /**
     * The connection events are sent over, or null until one is sent,
     * or once closed. Guarded by this object.
     */
    private Sender sender;

    public SyslogNotifier(PamSettings settings) {
        this.settings = settings;
    }

    /**
     * Where and how messages go, as the settings say.
     */
    private static final class Config {

        final String transport;
        final String host;
        final int port;
        final String authorities;
        final int facility;
        final String appName;

        Config(PamSettings settings) throws GuacamoleException {
            transport = (String) settings.get(SyslogSettings.TRANSPORT);
            host = (String) settings.get(SyslogSettings.HOST);
            port = (Integer) settings.get(SyslogSettings.PORT);
            authorities = (String) settings.get(SyslogSettings.CA_CERTIFICATES);
            facility = SyslogSettings.facility((String) settings.get(SyslogSettings.FACILITY));
            appName = (String) settings.get(SyslogSettings.APP_NAME);
            if (host == null)
                throw new GuacamoleClientException("No syslog server is set.");
        }

        /**
         * Whether a connection opened as configured here can be kept.
         */
        boolean sameConnection(Config other) {
            return transport.equals(other.transport) && host.equals(other.host) && port == other.port
                    && Objects.equals(authorities, other.authorities);
        }

        String describe() {
            return host + ":" + port + " over " + transport.toUpperCase();
        }

    }

    /**
     * A connection to the syslog server.
     */
    private interface Sender {

        Config getConfig();

        /**
         * Whether the server closed it, so it must be opened again.
         */
        boolean isClosed();

        void write(byte[] message) throws IOException;

        void close();

    }

    private static final class UdpSender implements Sender {

        private final Config config;
        private final DatagramSocket socket;

        UdpSender(Config config) throws IOException {
            this.config = config;
            this.socket = new DatagramSocket();
            socket.connect(new InetSocketAddress(config.host, config.port));
        }

        @Override
        public Config getConfig() {
            return config;
        }

        @Override
        public boolean isClosed() {
            return socket.isClosed();
        }

        @Override
        public void write(byte[] message) throws IOException {
            socket.send(new DatagramPacket(message, message.length));
        }

        @Override
        public void close() {
            socket.close();
        }

    }

    private static final class StreamSender implements Sender {

        private final Config config;
        private final Socket socket;
        private final InputStream input;
        private final OutputStream output;

        StreamSender(Config config, Socket socket) throws IOException {
            this.config = config;
            this.socket = socket;
            this.input = socket.getInputStream();
            this.output = socket.getOutputStream();
        }

        @Override
        public Config getConfig() {
            return config;
        }

        /**
         * Looks for the end of the stream: a syslog server sends nothing,
         * so anything read is its closing.
         */
        @Override
        public boolean isClosed() {
            try {
                socket.setSoTimeout(1);
                return input.read() < 0;
            }
            catch (SocketTimeoutException e) {
                return false;
            }
            catch (IOException e) {
                return true;
            }
        }

        @Override
        public void write(byte[] message) throws IOException {
            socket.setSoTimeout(WRITE_TIMEOUT_MS);
            output.write((message.length + " ").getBytes(StandardCharsets.US_ASCII));
            output.write(message);
            output.flush();
        }

        @Override
        public void close() {
            try {
                socket.close();
            }
            catch (IOException ignored) {
            }
        }

    }

    /**
     * Opens a connection as configured.
     */
    private static Sender open(Config config) throws GuacamoleException {

        try {

            if (SyslogSettings.UDP.equals(config.transport))
                return new UdpSender(config);

            Socket socket = new Socket();
            try {
                socket.connect(new InetSocketAddress(config.host, config.port), CONNECT_TIMEOUT_MS);
                socket.setSoTimeout(WRITE_TIMEOUT_MS);
                if (SyslogSettings.TLS.equals(config.transport))
                    socket = secure(config, socket);
                return new StreamSender(config, socket);
            }
            catch (IOException | GuacamoleException | RuntimeException e) {
                socket.close();
                throw e;
            }

        }
        catch (SSLHandshakeException e) {
            throw new GuacamoleServerException("The certificate of syslog server " + config.describe()
                    + " is not trusted, or does not name \"" + config.host + "\": " + e.getMessage()
                    + ". Add the CA certificate that issued it to the syslog settings.", e);
        }
        catch (IOException e) {
            throw new GuacamoleServerException("Unable to reach syslog server " + config.describe() + ": "
                    + e.getMessage(), e);
        }

    }

    /**
     * TLS over the connection, checking that the server's certificate is
     * trusted and names the host.
     */
    private static Socket secure(Config config, Socket plain) throws IOException, GuacamoleException {

        List<X509Certificate> authorities;
        try {
            authorities = Certificates.parseAuthorities(config.authorities);
        }
        catch (IllegalArgumentException e) {
            throw new GuacamoleClientException(e.getMessage());
        }

        SSLSocket socket;
        try {
            socket = (SSLSocket) Certificates.trusting(authorities).getSocketFactory()
                    .createSocket(plain, config.host, config.port, true);
        }
        catch (GeneralSecurityException e) {
            throw new GuacamoleServerException("Unable to set up TLS: " + e.getMessage(), e);
        }

        SSLParameters parameters = socket.getSSLParameters();
        parameters.setEndpointIdentificationAlgorithm("HTTPS");
        socket.setSSLParameters(parameters);
        socket.startHandshake();
        return socket;

    }

    @Override
    public String getName() {
        return "syslog";
    }

    /**
     * Whether syslog is on, closing the connection once it is off.
     */
    @Override
    public synchronized boolean isEnabled() throws GuacamoleException {
        boolean enabled = (Boolean) settings.get(SyslogSettings.ENABLED);
        if (!enabled)
            close();
        return enabled;
    }

    /**
     * Sends an event, holding the connection for it: closing it (at
     * shutdown) waits.
     */
    @Override
    public synchronized void send(Event event) throws GuacamoleException {

        Config config = new Config(settings);
        byte[] message = SyslogFormat.format(event, config.facility, config.appName);

        if (sender != null && (!sender.getConfig().sameConnection(config) || sender.isClosed()))
            close();
        if (sender == null)
            sender = open(config);

        try {
            sender.write(message);
        }
        catch (IOException first) {
            // Closed by the server meanwhile: once more, on a new connection
            close();
            sender = open(config);
            try {
                sender.write(message);
            }
            catch (IOException e) {
                close();
                throw new GuacamoleServerException("Unable to send to syslog server " + config.describe() + ": "
                        + e.getMessage(), e);
            }
        }

    }

    @Override
    public String test(String username) throws GuacamoleException {

        Config config = new Config(settings);
        Sender test = open(config);
        try {
            test.write(SyslogFormat.format(Event.of(EventType.TEST).actor(username), config.facility,
                    config.appName));
        }
        catch (IOException e) {
            throw new GuacamoleServerException("Unable to send to syslog server " + config.describe() + ": "
                    + e.getMessage(), e);
        }
        finally {
            test.close();
        }

        return "A test message was sent to syslog server " + config.describe() + "."
                + (SyslogSettings.UDP.equals(config.transport) ? " UDP never confirms it arrived: look for it there."
                : "");

    }

    @Override
    public synchronized void close() {
        if (sender != null)
            sender.close();
        sender = null;
    }

}
