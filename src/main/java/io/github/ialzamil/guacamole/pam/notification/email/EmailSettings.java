package io.github.ialzamil.guacamole.pam.notification.email;

import java.time.DateTimeException;
import java.time.ZoneId;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import jakarta.mail.internet.AddressException;
import jakarta.mail.internet.InternetAddress;

import io.github.ialzamil.guacamole.pam.Certificates;
import io.github.ialzamil.guacamole.pam.settings.Setting;

/**
 * The settings of email, on the settings page: off by default, and once on,
 * through a mail server requiring STARTTLS and checking its certificate,
 * unless told otherwise.
 */
public final class EmailSettings {

    private EmailSettings() {
    }

    public static final String STARTTLS = "starttls";
    public static final String TLS = "tls";
    public static final String NONE = "none";

    public static final Setting ENABLED = Setting.bool(Setting.Section.EMAIL, "pam-email-enabled", false);

    public static final Setting HOST = Setting.string(Setting.Section.EMAIL, "pam-email-host", 253,
            EmailSettings::checkHost).requiredWhen(ENABLED);

    /**
     * Port of mail submission (RFC 6409), with STARTTLS.
     */
    public static final Setting PORT = Setting.integer(Setting.Section.EMAIL, "pam-email-port", 587, 1, 65535);

    /**
     * How the connection is protected, the insecure way last.
     */
    public static final Setting SECURITY = Setting.options(Setting.Section.EMAIL, "pam-email-security",
            STARTTLS, TLS, NONE);

    public static final Setting CA_CERTIFICATES = Setting.text(Setting.Section.EMAIL, "pam-email-ca-certificates",
            7000, Certificates::parseAuthorities);

    public static final Setting USERNAME = Setting.string(Setting.Section.EMAIL, "pam-email-username", 256, null);

    public static final Setting PASSWORD = Setting.secret(Setting.Section.EMAIL, "pam-email-password", 256);

    public static final Setting FROM = Setting.string(Setting.Section.EMAIL, "pam-email-from", 256,
            EmailSettings::checkAddress).requiredWhen(ENABLED);

    /**
     * An address receiving what administrators receive, such as a security
     * team's.
     */
    public static final Setting ADMIN_ADDRESS = Setting.string(Setting.Section.EMAIL, "pam-email-admin-address", 256,
            EmailSettings::checkAddress);

    /**
     * Guacamole's address, for links in emails.
     */
    public static final Setting LINK = Setting.string(Setting.Section.EMAIL, "pam-email-link", 512,
            EmailSettings::checkLink);

    /**
     * The time zone of the times emails show, such as "Asia/Riyadh".
     */
    public static final Setting TIME_ZONE = Setting.string(Setting.Section.EMAIL, "pam-email-time-zone", "UTC", 64,
            EmailSettings::checkZone);

    /**
     * The language of emails to users who chose none, and to the address
     * receiving what administrators receive.
     */
    public static final Setting LANGUAGE = Setting.string(Setting.Section.EMAIL, "pam-email-language",
            EmailLanguages.ENGLISH, 16, EmailLanguages::checkCode);

    public static final List<Setting> ALL = Collections.unmodifiableList(Arrays.asList(
            ENABLED, HOST, PORT, SECURITY, CA_CERTIFICATES, USERNAME, PASSWORD, FROM, ADMIN_ADDRESS, LINK,
            TIME_ZONE, LANGUAGE));

    static void checkHost(String host) {
        if (!host.matches("[A-Za-z0-9._:\\[\\]-]+"))
            throw new IllegalArgumentException("not a host name or address.");
    }

    /**
     * Refuses what is not one email address, such as "pam@example.org".
     */
    static void checkAddress(String address) {
        try {
            InternetAddress[] parsed = InternetAddress.parse(address, true);
            if (parsed.length != 1 || parsed[0].getAddress().indexOf('@') < 0)
                throw new IllegalArgumentException("not an email address.");
            parsed[0].validate();
        }
        catch (AddressException e) {
            throw new IllegalArgumentException("not an email address.");
        }
    }

    static void checkZone(String zone) {
        try {
            ZoneId.of(zone);
        }
        catch (DateTimeException e) {
            throw new IllegalArgumentException("not a time zone, such as UTC or Europe/Paris.");
        }
    }

    static void checkLink(String link) {
        if (!link.matches("https?://[^\\s]+"))
            throw new IllegalArgumentException("not an http:// or https:// address.");
    }

}
