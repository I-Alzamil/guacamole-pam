package io.github.ialzamil.guacamole.pam.ha;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HashSet;
import java.util.Set;
import java.util.jar.JarFile;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.environment.Environment;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * What guacamole.properties sets for this extension: its own "pam-ha-*"
 * properties, and those of Guacamole and its extensions that it follows,
 * such as the ban extension's limits. Also which of those extensions are
 * installed: what they do on each server alone is only shared if they are.
 */
final class Config {

    private static final Logger logger = LoggerFactory.getLogger(Config.class);

    private static final Pattern NAMESPACE = Pattern.compile("\"namespace\"\\s*:\\s*\"([^\"]+)\"");

    /**
     * The URL other servers reach this one at, such as
     * "http://10.0.0.1:8080/guacamole", to fetch its recordings; null if
     * not set.
     */
    final String url;

    /**
     * The secret servers give each other to fetch recordings; null if not
     * set.
     */
    final String secret;

    /**
     * The host name other servers reach the guacd of this server at, where
     * its connections name it "localhost"; null if not set.
     */
    final String guacdHostname;

    /**
     * guacd as Guacamole reaches it by default.
     */
    final String defaultGuacdHostname;
    final int defaultGuacdPort;
    final boolean defaultGuacdSsl;

    /**
     * Minutes after which a login not used on any server ends.
     */
    final int sessionTimeoutMinutes;

    /**
     * The ban extension's limits, if installed and enabled: failed logins
     * of an address before it is banned, and for how long, in seconds.
     */
    final boolean ban;
    final int banMaxAttempts;
    final int banDurationSeconds;

    /**
     * Whether the TOTP extension is installed, and how long its codes last,
     * in seconds.
     */
    final boolean totp;
    final int totpPeriodSeconds;

    /**
     * Whether the history recording storage extension is installed, and
     * where it finds recordings.
     */
    final boolean recordings;
    final File recordingSearchPath;

    Config(Environment environment) throws GuacamoleException {

        url = trimmed(environment.getProperty(Settings.string("pam-ha-url")));
        secret = trimmed(environment.getProperty(Settings.string("pam-ha-secret")));
        guacdHostname = trimmed(environment.getProperty(Settings.string("pam-ha-guacd-hostname")));

        defaultGuacdHostname = environment.getProperty(Settings.string("guacd-hostname"), "localhost");
        defaultGuacdPort = environment.getProperty(Settings.integer("guacd-port"), 4822);
        defaultGuacdSsl = environment.getProperty(Settings.bool("guacd-ssl"), false);

        sessionTimeoutMinutes = environment.getProperty(Settings.integer("api-session-timeout"), 60);

        Set<String> installed = installedExtensions(environment.getGuacamoleHome());

        banMaxAttempts = environment.getProperty(Settings.integer("ban-max-invalid-attempts"), 5);
        banDurationSeconds = environment.getProperty(Settings.integer("ban-address-duration"), 300);
        // As the ban extension: any of its limits at zero or less turns
        // banning off
        int banMaxAddresses = environment.getProperty(Settings.integer("ban-max-addresses"), 10485760);
        ban = installed.contains("ban") && banMaxAttempts > 0 && banDurationSeconds > 0 && banMaxAddresses > 0;

        totp = installed.contains("totp");
        totpPeriodSeconds = environment.getProperty(Settings.integer("totp-period"), 30);

        recordings = installed.contains("recording-storage");
        String searchPath = environment.getProperty(Settings.string("recording-search-path"));
        recordingSearchPath = new File(searchPath != null ? searchPath : "/var/lib/guacamole/recordings");

    }

    /**
     * Whether recordings are fetched from, and served to, other servers:
     * if recordings are shown, and this server's URL and the secret are
     * set.
     */
    boolean fetchesRecordings() {
        return recordings && url != null && secret != null;
    }

    /**
     * Whether another server gave the secret servers share: never, if none
     * is set.
     */
    boolean isSecret(String given) {
        return given != null && secret != null && MessageDigest.isEqual(given.getBytes(StandardCharsets.UTF_8),
                secret.getBytes(StandardCharsets.UTF_8));
    }

    private static String trimmed(String value) {
        return value == null || value.trim().isEmpty() ? null : value.trim();
    }

    /**
     * The namespaces of the extensions in GUACAMOLE_HOME/extensions, as
     * their guac-manifest.json names them.
     */
    static Set<String> installedExtensions(File guacamoleHome) {

        Set<String> namespaces = new HashSet<>();
        File[] jars = new File(guacamoleHome, "extensions").listFiles((dir, name) -> name.endsWith(".jar"));
        if (jars == null)
            return namespaces;

        for (File jar : jars) {
            try (JarFile file = new JarFile(jar)) {
                ZipEntry manifest = file.getEntry("guac-manifest.json");
                if (manifest == null)
                    continue;
                try (InputStream input = file.getInputStream(manifest)) {
                    Matcher matcher = NAMESPACE.matcher(new String(input.readAllBytes(), StandardCharsets.UTF_8));
                    if (matcher.find())
                        namespaces.add(matcher.group(1));
                }
            }
            catch (IOException e) {
                logger.debug("Unable to read the manifest of {}.", jar, e);
            }
        }

        return namespaces;

    }

}
