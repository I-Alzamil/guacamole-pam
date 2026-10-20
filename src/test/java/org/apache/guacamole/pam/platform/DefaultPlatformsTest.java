package org.apache.guacamole.pam.platform;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.List;

import org.apache.guacamole.GuacamoleClientException;
import org.junit.Test;

/**
 * The default platforms are valid as an editor would save them.
 */
public class DefaultPlatformsTest {

    @Test
    public void readsTheDefaults() {
        List<Platform> defaults = DefaultPlatforms.read();
        assertEquals(2, defaults.size());
        assertEquals("Linux (passwd)", defaults.get(0).getName());
        assertEquals("Windows (net user)", defaults.get(1).getName());
    }

    @Test
    public void defaultsAreValid() throws GuacamoleClientException {
        for (Platform platform : DefaultPlatforms.read()) {
            Platform clean = PlatformRepository.sanitize(platform, null);
            assertEquals("ssh", clean.getType());
            assertTrue(clean.getSettings().get("script").contains("<NEWPASS>"));
        }
    }

    @Test
    public void eachReadIsNew() {
        DefaultPlatforms.read().get(0).setName("changed");
        assertEquals("Linux (passwd)", DefaultPlatforms.read().get(0).getName());
    }

}
