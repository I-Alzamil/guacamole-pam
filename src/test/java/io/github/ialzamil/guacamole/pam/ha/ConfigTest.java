package io.github.ialzamil.guacamole.pam.ha;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.jar.JarOutputStream;
import java.util.zip.ZipEntry;

import org.apache.guacamole.GuacamoleException;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

/**
 * What guacamole.properties and the extensions installed set for this
 * extension.
 */
public class ConfigTest {

    @Rule
    public TemporaryFolder folder = new TemporaryFolder();

    /**
     * A GUACAMOLE_HOME with extensions of the given namespaces.
     */
    private File home(String... namespaces) throws IOException {
        File home = folder.newFolder();
        File extensions = new File(home, "extensions");
        extensions.mkdir();
        for (String namespace : namespaces) {
            try (JarOutputStream jar = new JarOutputStream(new FileOutputStream(
                    new File(extensions, namespace + ".jar")))) {
                jar.putNextEntry(new ZipEntry("guac-manifest.json"));
                jar.write(("{ \"guacamoleVersion\" : \"1.6.0\", \"namespace\" : \"" + namespace + "\" }")
                        .getBytes(StandardCharsets.UTF_8));
            }
        }
        new File(extensions, "notes.txt").createNewFile();
        return home;
    }

    @Test
    public void readsDefaults() throws GuacamoleException, IOException {
        Config config = new Config(new TestEnvironment().home(home()));
        assertNull(config.url);
        assertNull(config.secret);
        assertNull(config.guacdHostname);
        assertEquals("localhost", config.defaultGuacdHostname);
        assertEquals(4822, config.defaultGuacdPort);
        assertFalse(config.defaultGuacdSsl);
        assertEquals(60, config.sessionTimeoutMinutes);
        assertFalse(config.ban);
        assertFalse(config.totp);
        assertFalse(config.recordings);
        assertEquals(new File("/var/lib/guacamole/recordings"), config.recordingSearchPath);
    }

    @Test
    public void followsInstalledExtensions() throws GuacamoleException, IOException {
        Config config = new Config(new TestEnvironment("pam-ha-url", " http://a:8080/guacamole ",
                "pam-ha-secret", "s3cret", "ban-max-invalid-attempts", "3", "totp-period", "60",
                "recording-search-path", "/rec").home(home("ban", "totp", "recording-storage", "jdbc")));
        assertEquals("http://a:8080/guacamole", config.url);
        assertTrue(config.ban);
        assertEquals(3, config.banMaxAttempts);
        assertEquals(300, config.banDurationSeconds);
        assertTrue(config.totp);
        assertEquals(60, config.totpPeriodSeconds);
        assertTrue(config.recordings);
        assertTrue(config.fetchesRecordings());
        assertEquals(new File("/rec"), config.recordingSearchPath);
    }

    @Test
    public void bansOnlyAsTheBanExtension() throws GuacamoleException, IOException {
        assertFalse(new Config(new TestEnvironment("ban-max-invalid-attempts", "0").home(home("ban"))).ban);
        assertFalse(new Config(new TestEnvironment("ban-address-duration", "0").home(home("ban"))).ban);
    }

    @Test
    public void fetchesRecordingsOnlyWithUrlAndSecret() throws GuacamoleException, IOException {
        assertFalse(new Config(new TestEnvironment("pam-ha-url", "http://a")
                .home(home("recording-storage"))).fetchesRecordings());
        assertFalse(new Config(new TestEnvironment("pam-ha-url", "http://a", "pam-ha-secret", "s")
                .home(home())).fetchesRecordings());
    }

    @Test
    public void readsNoExtensionsWithoutTheirFolder() throws IOException {
        assertTrue(Config.installedExtensions(folder.newFolder()).isEmpty());
    }

}
