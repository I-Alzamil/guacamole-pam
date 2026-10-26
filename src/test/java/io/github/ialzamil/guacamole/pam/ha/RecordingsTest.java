package io.github.ialzamil.guacamole.pam.ha;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.io.File;
import java.io.IOException;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleResourceNotFoundException;
import org.apache.guacamole.GuacamoleSecurityException;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

/**
 * Which recordings this server gives other servers.
 */
public class RecordingsTest {

    private static final String UUID = "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0";

    @Rule
    public TemporaryFolder folder = new TemporaryFolder();

    private Recordings recordings;

    private File root;

    @Before
    public void setUp() throws IOException, GuacamoleException {
        root = folder.newFolder("recordings");
        new File(root, UUID).createNewFile();
        File directory = new File(root, UUID.replace('0', '1'));
        directory.mkdir();
        new File(directory, "typescript").createNewFile();
        folder.newFile("outside");
        recordings = new Recordings(null, new Config(new TestEnvironment("pam-ha-secret", "s3cret",
                "recording-search-path", root.getPath()).home(folder.getRoot())));
    }

    @Test
    public void givesRecordingsWithTheSecret() throws GuacamoleException, IOException {
        assertEquals(new File(root, UUID).getCanonicalFile(), recordings.file("s3cret", UUID));
        String inDirectory = UUID.replace('0', '1') + "/typescript";
        assertEquals(new File(root, inDirectory).getCanonicalFile(), recordings.file("s3cret", inDirectory));
    }

    @Test
    public void refusesWithoutTheSecret() throws GuacamoleException {
        for (String secret : new String[] { null, "", "s3cre", "s3cret " }) {
            try {
                recordings.file(secret, UUID);
                fail("Given with secret " + secret);
            }
            catch (GuacamoleSecurityException e) {
                // Refused
            }
        }
    }

    @Test
    public void givesNothingElse() throws GuacamoleException {
        for (String path : new String[] { "outside", "../outside", UUID + "/../../outside", UUID + "/..",
                UUID + "/", "not-a-uuid", UUID.replace('0', '1') + "/missing", UUID + "/a/b",
                UUID.replace('0', '1') }) {
            try {
                recordings.file("s3cret", path);
                fail("Given " + path);
            }
            catch (GuacamoleResourceNotFoundException e) {
                // Refused
            }
        }
    }

}
