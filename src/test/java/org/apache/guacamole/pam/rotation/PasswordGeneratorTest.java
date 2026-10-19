package org.apache.guacamole.pam.rotation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class PasswordGeneratorTest {

    private final PasswordGenerator generator = new PasswordGenerator();

    @Test
    public void containsEveryCharacterClass() {
        for (int i = 0; i < 500; i++) {
            String password = generator.generate(PasswordGenerator.MIN_LENGTH);
            assertTrue(password, password.matches(".*[a-z].*"));
            assertTrue(password, password.matches(".*[A-Z].*"));
            assertTrue(password, password.matches(".*[0-9].*"));
            assertTrue(password, password.matches(".*[-_=+.,:@].*"));
            assertTrue(password, password.matches("[a-zA-Z0-9\\-_=+.,:@]+"));
        }
    }

    @Test
    public void clampsLength() {
        assertEquals(PasswordGenerator.MIN_LENGTH, generator.generate(4).length());
        assertEquals(PasswordGenerator.MAX_LENGTH, generator.generate(1000).length());
        assertEquals(30, generator.generate(30).length());
    }

}
