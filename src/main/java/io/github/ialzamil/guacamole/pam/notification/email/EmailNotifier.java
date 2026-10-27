package io.github.ialzamil.guacamole.pam.notification.email;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import javax.net.ssl.SSLHandshakeException;

import jakarta.mail.AuthenticationFailedException;
import jakarta.mail.Message;
import jakarta.mail.MessagingException;
import jakarta.mail.SendFailedException;
import jakarta.mail.Session;
import jakarta.mail.Transport;
import jakarta.mail.internet.AddressException;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;

import org.apache.guacamole.GuacamoleClientException;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleServerException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.github.ialzamil.guacamole.pam.Certificates;
import io.github.ialzamil.guacamole.pam.notification.Event;
import io.github.ialzamil.guacamole.pam.notification.EventType;
import io.github.ialzamil.guacamole.pam.notification.Notifier;
import io.github.ialzamil.guacamole.pam.settings.PamSettings;

/**
 * Emails events to those they concern (see {@link Audience}), at the
 * address of their Guacamole profile, and to the address receiving what
 * administrators receive if set, through an SMTP server: with STARTTLS
 * required (the default), or TLS from the start, checking the server's
 * certificate and name either way, or unencrypted. The emails of an event
 * are sent on one connection, opened for them.
 */
public final class EmailNotifier implements Notifier {

    private static final Logger logger = LoggerFactory.getLogger(EmailNotifier.class);

    private static final String TIMEOUT_MS = "10000";

    private final PamSettings settings;

    private final Directory directory;

    private final EmailPreferences preferences;

    public EmailNotifier(PamSettings settings, Directory directory, EmailPreferences preferences) {
        this.settings = settings;
        this.directory = directory;
        this.preferences = preferences;
    }

    /**
     * The mail server and sender, as the settings say.
     */
    private static final class Config {

        final String host;
        final int port;
        final String security;
        final String authorities;
        final String username;
        final String password;
        final String from;
        final String adminAddress;
        final String link;

        Config(PamSettings settings) throws GuacamoleException {
            host = (String) settings.get(EmailSettings.HOST);
            port = (Integer) settings.get(EmailSettings.PORT);
            security = (String) settings.get(EmailSettings.SECURITY);
            authorities = (String) settings.get(EmailSettings.CA_CERTIFICATES);
            username = (String) settings.get(EmailSettings.USERNAME);
            password = settings.getSecret(EmailSettings.PASSWORD);
            from = (String) settings.get(EmailSettings.FROM);
            adminAddress = (String) settings.get(EmailSettings.ADMIN_ADDRESS);
            link = (String) settings.get(EmailSettings.LINK);
            if (host == null)
                throw new GuacamoleClientException("No mail server is set.");
            if (from == null)
                throw new GuacamoleClientException("No sender address is set.");
        }

        String describe() {
            return host + ":" + port + (EmailSettings.STARTTLS.equals(security) ? " with STARTTLS"
                    : EmailSettings.TLS.equals(security) ? " over TLS" : " unencrypted");
        }

    }

    /**
     * Where users and their preferences come from.
     */
    private final Audience.Source source = new Audience.Source() {

        @Override
        public Set<String> getAdministrators() throws GuacamoleException {
            return directory.getAdministrators();
        }

        @Override
        public Set<String> getApproversOf(String connectionIdentifier) throws GuacamoleException {
            return directory.getApproversOf(connectionIdentifier);
        }

        @Override
        public Map<String, Map<Audience.Role, Boolean>> getPreferences(Collection<String> usernames)
                throws GuacamoleException {
            return preferences.get(usernames);
        }

    };

    @Override
    public String getName() {
        return "email";
    }

    @Override
    public boolean isEnabled() throws GuacamoleException {
        return (Boolean) settings.get(EmailSettings.ENABLED);
    }

    @Override
    public void send(Event event) throws GuacamoleException {

        Config config = new Config(settings);
        Map<String, Audience.Role> audience = Audience.of(event, source);
        Map<String, String> addresses = directory.getAddresses(audience.keySet());

        // One email per address, as the role of the first user having it;
        // the extra address as what administrators receive (no role)
        Map<String, Audience.Role> recipients = new LinkedHashMap<>();
        Set<String> seen = new HashSet<>();
        for (Map.Entry<String, Audience.Role> entry : audience.entrySet()) {
            String address = addresses.get(entry.getKey());
            if (address == null)
                logger.debug("No email to \"{}\" about {}: no email address.", entry.getKey(),
                        event.getType().getId());
            else if (seen.add(address.toLowerCase()))
                recipients.put(address, entry.getValue());
        }
        if (config.adminAddress != null && seen.add(config.adminAddress.toLowerCase()))
            recipients.put(config.adminAddress, null);

        if (recipients.isEmpty())
            return;

        deliver(config, (session, transport) -> {
            for (Map.Entry<String, Audience.Role> recipient : recipients.entrySet())
                sendOne(session, transport, config, event, recipient.getKey(), recipient.getValue());
        });

    }

    /**
     * Sends one email, logging (and skipping) an address the server
     * refuses.
     */
    private static void sendOne(Session session, Transport transport, Config config, Event event, String to,
            Audience.Role role) throws MessagingException {
        MimeMessage message = new MimeMessage(session);
        message.setFrom(new InternetAddress(config.from, true));
        message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(to, true));
        message.setSubject(EmailText.subject(event), "UTF-8");
        message.setText(EmailText.body(event, role, config.link), "UTF-8");
        message.setSentDate(new Date(event.getTime()));
        message.setHeader("Auto-Submitted", "auto-generated");
        message.saveChanges();
        try {
            transport.sendMessage(message, message.getAllRecipients());
        }
        catch (SendFailedException e) {
            logger.warn("The mail server refused to send to \"{}\": {}", to, e.getMessage());
        }
    }

    @FunctionalInterface
    private interface Delivery {
        void run(Session session, Transport transport) throws MessagingException;
    }

    /**
     * Connects to the mail server, runs the delivery, and disconnects.
     * Jakarta Mail finds its providers through the thread's class loader,
     * which is the web application's, not this extension's: set to this
     * one meanwhile.
     */
    private static void deliver(Config config, Delivery delivery) throws GuacamoleException {

        Thread thread = Thread.currentThread();
        ClassLoader previous = thread.getContextClassLoader();
        thread.setContextClassLoader(EmailNotifier.class.getClassLoader());
        try {
            Session session = Session.getInstance(properties(config));
            try (Transport transport = session.getTransport("smtp")) {
                transport.connect(config.host, config.port, config.username, config.password);
                delivery.run(session, transport);
            }
        }
        catch (AuthenticationFailedException e) {
            throw new GuacamoleServerException("Mail server " + config.describe() + " refused the username or"
                    + " password" + (e.getMessage() == null ? "." : ": " + e.getMessage().trim()), e);
        }
        catch (MessagingException e) {
            throw new GuacamoleServerException(describe(config, e), e);
        }
        finally {
            thread.setContextClassLoader(previous);
        }

    }

    private static String describe(Config config, MessagingException e) {
        for (Throwable cause = e.getCause(); cause != null; cause = cause.getCause()) {
            if (cause instanceof SSLHandshakeException)
                return "The certificate of mail server " + config.describe() + " is not trusted, or does not name \""
                        + config.host + "\": " + cause.getMessage() + ". Add the CA certificate that issued it to"
                        + " the email settings.";
        }
        if (e.getCause() instanceof IOException)
            return "Unable to reach mail server " + config.describe() + ": " + e.getCause().getMessage();
        return "Mail server " + config.describe() + " failed: " + e.getMessage();
    }

    /**
     * Jakarta Mail's properties: timeouts, the sender, the protection asked
     * for, and the CA certificates trusted if set.
     */
    private static Properties properties(Config config) throws GuacamoleException {

        Properties properties = new Properties();
        properties.put("mail.smtp.connectiontimeout", TIMEOUT_MS);
        properties.put("mail.smtp.timeout", TIMEOUT_MS);
        properties.put("mail.smtp.writetimeout", TIMEOUT_MS);
        properties.put("mail.smtp.auth", Boolean.toString(config.username != null));
        try {
            properties.put("mail.smtp.from", new InternetAddress(config.from, true).getAddress());
        }
        catch (AddressException e) {
            throw new GuacamoleClientException("The sender address is not valid: " + e.getMessage());
        }

        if (EmailSettings.NONE.equals(config.security))
            return properties;

        if (EmailSettings.STARTTLS.equals(config.security)) {
            properties.put("mail.smtp.starttls.enable", "true");
            properties.put("mail.smtp.starttls.required", "true");
        }
        else
            properties.put("mail.smtp.ssl.enable", "true");

        properties.put("mail.smtp.ssl.checkserveridentity", "true");
        try {
            properties.put("mail.smtp.ssl.socketFactory",
                    Certificates.trusting(Certificates.parseAuthorities(config.authorities)).getSocketFactory());
        }
        catch (IllegalArgumentException e) {
            throw new GuacamoleClientException(e.getMessage());
        }
        catch (GeneralSecurityException e) {
            throw new GuacamoleServerException("Unable to set up TLS: " + e.getMessage(), e);
        }
        return properties;

    }

    /**
     * Emails a test to the administrator's own address, or else to the one
     * receiving what administrators receive.
     */
    @Override
    public String test(String username) throws GuacamoleException {

        Config config = new Config(settings);
        String own = directory.getAddresses(Collections.singleton(username)).get(username);
        String to = own != null ? own : config.adminAddress;
        if (to == null)
            throw new GuacamoleClientException("Your Guacamole user has no email address to send the test to: set"
                    + " one in your profile (Settings > Users), or the address receiving administrators' emails.");

        Event event = Event.of(EventType.TEST).actor(username);
        deliver(config, (session, transport) -> sendOne(session, transport, config, event, to,
                own != null ? Audience.Role.ADMINISTRATOR : null));
        return "A test email was sent to " + to + " through mail server " + config.describe() + ".";

    }

    @Override
    public void close() {
    }

}
