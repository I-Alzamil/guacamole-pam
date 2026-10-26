package io.github.ialzamil.guacamole.pam.notification.syslog;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import io.github.ialzamil.guacamole.pam.Certificates;
import io.github.ialzamil.guacamole.pam.settings.Setting;

/**
 * The settings of syslog, on the settings page: off by default, and once
 * on, over TLS checking the server's certificate unless told otherwise.
 */
public final class SyslogSettings {

    private SyslogSettings() {
    }

    public static final String TLS = "tls";
    public static final String TCP = "tcp";
    public static final String UDP = "udp";

    /**
     * Port of syslog over TLS (RFC 5425).
     */
    static final int TLS_PORT = 6514;

    public static final Setting ENABLED = Setting.bool(Setting.Section.SYSLOG, "pam-syslog-enabled", false);

    public static final Setting HOST = Setting.string(Setting.Section.SYSLOG, "pam-syslog-host", 253,
            SyslogSettings::checkHost).requiredWhen(ENABLED);

    public static final Setting PORT = Setting.integer(Setting.Section.SYSLOG, "pam-syslog-port", TLS_PORT, 1, 65535);

    /**
     * How messages are sent, the insecure ways last.
     */
    public static final Setting TRANSPORT = Setting.options(Setting.Section.SYSLOG, "pam-syslog-transport",
            TLS, TCP, UDP);

    public static final Setting CA_CERTIFICATES = Setting.text(Setting.Section.SYSLOG, "pam-syslog-ca-certificates",
            7000, Certificates::parseAuthorities);

    /**
     * The facility of messages, by name, with its number (RFC 5424).
     */
    public static final Setting FACILITY = Setting.options(Setting.Section.SYSLOG, "pam-syslog-facility",
            "authpriv", "auth", "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7",
            "user", "daemon");

    /**
     * What messages say they come from, "guacamole-pam" unless set.
     */
    public static final Setting APP_NAME = Setting.string(Setting.Section.SYSLOG, "pam-syslog-app-name",
            SyslogFormat.MAX_APP_NAME, SyslogFormat::checkAppName);

    public static final List<Setting> ALL = Collections.unmodifiableList(Arrays.asList(
            ENABLED, HOST, PORT, TRANSPORT, CA_CERTIFICATES, FACILITY, APP_NAME));

    /**
     * Refuses what cannot be a host name or address.
     */
    static void checkHost(String host) {
        if (!host.matches("[A-Za-z0-9._:\\[\\]-]+"))
            throw new IllegalArgumentException("not a host name or address.");
    }

    /**
     * The number of a facility's name.
     */
    static int facility(String name) {
        switch (name) {
            case "user": return 1;
            case "daemon": return 3;
            case "auth": return 4;
            case "authpriv": return 10;
            default:
                if (name.matches("local[0-7]"))
                    return 16 + (name.charAt(5) - '0');
                return 10;
        }
    }

}
