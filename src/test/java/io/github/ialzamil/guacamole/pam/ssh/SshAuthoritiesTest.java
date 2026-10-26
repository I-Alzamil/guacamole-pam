package io.github.ialzamil.guacamole.pam.ssh;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.List;

import org.junit.Test;

public class SshAuthoritiesTest {

    private static final String CA = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINu94m75u7DzmV948pYokfMpMYIDvYko5ecSZp6Hxlcd";

    @Test
    public void readsPublicKeyLinesAndKnownHostsLines() {
        List<byte[]> keys = SshAuthorities.parse(CA + " test-ca\n\n# a comment\n@cert-authority *.example.org " + CA);
        assertEquals(2, keys.size());
        assertEquals("ssh-ed25519", PinnedHostKeyRepository.type(keys.get(0)));
        assertTrue(new PinnedHostKeyRepository(null, false, "host", 22, keys).hasAuthorities());
    }

    @Test
    public void emptyIsNone() {
        assertTrue(SshAuthorities.parse(null).isEmpty());
        assertTrue(SshAuthorities.parse(" \n").isEmpty());
    }

    @Test
    public void aPinnedKeyTakesPrecedence() {
        List<byte[]> keys = SshAuthorities.parse(CA);
        assertEquals(false, new PinnedHostKeyRepository("SHA256:abc", false, "host", 22, keys).hasAuthorities());
    }

    @Test
    public void refusesWhatIsNotAKey() {
        refused("ssh-ed25519");
        refused("ssh-ed25519 not-base64!");
        refused("ssh-rsa " + CA.split(" ")[1]);
    }

    private static void refused(String lines) {
        try {
            SshAuthorities.parse(lines);
            fail("accepted " + lines);
        }
        catch (IllegalArgumentException e) {
            assertTrue(e.getMessage(), e.getMessage().startsWith("SSH CA key line 1"));
        }
    }

}
