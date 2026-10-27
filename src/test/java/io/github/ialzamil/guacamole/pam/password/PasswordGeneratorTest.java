package io.github.ialzamil.guacamole.pam.password;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.apache.guacamole.GuacamoleClientException;
import org.junit.Test;

/**
 * Passwords following the rules of password policies, many times over since
 * they are random, and rules refused as unable to make any.
 */
public class PasswordGeneratorTest {

    private static final int ROUNDS = 500;

    private final PasswordGenerator generator = new PasswordGenerator();

    private static int count(String password, String regex) {
        return password.replaceAll("[^" + regex + "]", "").length();
    }

    /**
     * As every rotation made them before password policies: 24 characters,
     * every kind at least once, the safe symbols only, nothing ambiguous.
     */
    @Test
    public void defaultsAsBefore() throws GuacamoleClientException {
        PasswordRules rules = PasswordRules.defaults().validate();
        for (int i = 0; i < ROUNDS; i++) {
            String password = generator.generate(rules);
            assertEquals(24, password.length());
            assertTrue(password, password.matches(".*[a-z].*") && password.matches(".*[A-Z].*")
                    && password.matches(".*[0-9].*") && password.matches(".*[-_=+.,:@].*"));
            assertTrue(password, password.matches("[a-zA-Z0-9\\-_=+.,:@]+"));
            assertFalse(password, password.matches(".*[lIO01].*"));
        }
    }

    @Test
    public void meetsEachMinimum() throws GuacamoleClientException {
        PasswordRules rules = PasswordRules.defaults();
        rules.setLength(12);
        rules.setMinLowercase(2);
        rules.setMinUppercase(3);
        rules.setMinDigits(4);
        rules.setMinSymbols(3);
        rules.validate();
        for (int i = 0; i < ROUNDS; i++) {
            String password = generator.generate(rules);
            assertEquals(12, password.length());
            assertTrue(password, count(password, "a-z") >= 2);
            assertTrue(password, count(password, "A-Z") >= 3);
            assertTrue(password, count(password, "0-9") >= 4);
            assertTrue(password, count(password, "\\-_=+.,:@") >= 3);
        }
    }

    /**
     * As a mainframe (RACF) may require: 8 characters, letters and digits
     * only, starting with a letter.
     */
    @Test
    public void shortWithoutSymbolsStartingWithALetter() throws GuacamoleClientException {
        PasswordRules rules = PasswordRules.defaults();
        rules.setLength(8);
        rules.setSymbols(false);
        rules.setMinLowercase(0);
        rules.setMinUppercase(0);
        rules.setStartWithLetter(true);
        rules.validate();
        assertEquals("", rules.getSymbolSet());
        for (int i = 0; i < ROUNDS; i++) {
            String password = generator.generate(rules);
            assertTrue(password, password.matches("[a-zA-Z][a-zA-Z0-9]{7}"));
            assertTrue(password, password.matches(".*[0-9].*"));
        }
    }

    @Test
    public void onlyTheKindsAndSymbolsAllowed() throws GuacamoleClientException {
        PasswordRules rules = PasswordRules.defaults();
        rules.setLowercase(false);
        rules.setUppercase(false);
        rules.setMinDigits(10);
        rules.setSymbolSet("#!#!");
        rules.setExcludeAmbiguous(false);
        rules.validate();
        assertEquals("#!", rules.getSymbolSet());
        assertEquals(0, rules.getMinLowercase());
        boolean sawZeroOrOne = false;
        for (int i = 0; i < ROUNDS; i++) {
            String password = generator.generate(rules);
            assertTrue(password, password.matches("[0-9#!]{24}"));
            assertTrue(password, count(password, "0-9") >= 10 && count(password, "#!") >= 1);
            sawZeroOrOne |= password.matches(".*[01].*");
        }
        assertTrue("Ambiguous characters are allowed when asked", sawZeroOrOne);
    }

    /**
     * "${" starts a Guacamole token, which Guacamole would replace in a
     * password stored in a connection's parameters: never made, even when
     * most characters are "$" and "{".
     */
    @Test
    public void neverStartsAGuacamoleToken() throws GuacamoleClientException {
        PasswordRules rules = PasswordRules.defaults();
        rules.setLength(6);
        rules.setLowercase(false);
        rules.setUppercase(false);
        rules.setMinDigits(0);
        rules.setSymbolSet("${");
        rules.setMinSymbols(5);
        rules.validate();
        boolean sawBoth = false;
        for (int i = 0; i < ROUNDS * 4; i++) {
            String password = generator.generate(rules);
            assertFalse(password, password.contains("${"));
            sawBoth |= password.contains("$") && password.contains("{");
        }
        assertTrue("Both symbols are still used", sawBoth);
    }

    /**
     * Rules leaving almost nothing but "$" and "{", where no shuffle would
     * avoid "${": made at once still.
     */
    @Test(timeout = 5000)
    public void endsEvenWhenAlmostEveryArrangementStartsAToken() throws GuacamoleClientException {
        PasswordRules rules = PasswordRules.defaults();
        rules.setLength(64);
        rules.setLowercase(false);
        rules.setUppercase(false);
        rules.setDigits(false);
        rules.setStartWithLetter(false);
        rules.setSymbolSet("${");
        rules.validate();
        for (int i = 0; i < ROUNDS; i++) {
            String password = generator.generate(rules);
            assertEquals(64, password.length());
            assertFalse(password, password.contains("${"));
        }
    }

    @Test
    public void estimatesStrength() throws GuacamoleClientException {
        // 25 + 24 + 8 + 8 characters (lowercase without l, uppercase without I and O, digits without 0 and 1)
        assertEquals((int) Math.floor(24 * Math.log(65) / Math.log(2)),
                PasswordGenerator.strengthBits(PasswordRules.defaults().validate()));
        PasswordRules digits = PasswordRules.defaults();
        digits.setLength(8);
        digits.setLowercase(false);
        digits.setUppercase(false);
        digits.setSymbols(false);
        digits.setExcludeAmbiguous(false);
        assertEquals(26, PasswordGenerator.strengthBits(digits.validate()));
    }

    @Test
    public void refusesRulesMakingNoPassword() {
        refuses(rules -> rules.setLength(3), "The length must be from 4 to 128.");
        refuses(rules -> rules.setLength(129), "The length must be from 4 to 128.");
        refuses(rules -> {
            rules.setLowercase(false);
            rules.setUppercase(false);
            rules.setDigits(false);
            rules.setSymbols(false);
        }, "Allow at least one kind of character.");
        refuses(rules -> rules.setMinDigits(-1), "Minimums cannot be negative.");
        refuses(rules -> {
            rules.setMinLowercase(Integer.MAX_VALUE);
            rules.setMinUppercase(Integer.MAX_VALUE);
        }, "A minimum cannot be more than the length of 24.");
        refuses(rules -> {
            rules.setLength(8);
            rules.setMinDigits(6);
            rules.setMinSymbols(3);
        }, "The minimums add up to 11 characters, more than the length of 8.");
        refuses(rules -> rules.setSymbolSet(""), "Give the symbols to use, or do not allow symbols.");
        refuses(rules -> rules.setSymbolSet("-a"), "Symbols must be printable ASCII characters other than letters,"
                + " digits and spaces.");
        refuses(rules -> rules.setSymbolSet("- "), "Symbols must be printable ASCII characters other than letters,"
                + " digits and spaces.");
        refuses(rules -> {
            rules.setLowercase(false);
            rules.setUppercase(false);
            rules.setStartWithLetter(true);
        }, "Passwords cannot start with a letter without letters allowed.");
    }

    private interface Change {
        void apply(PasswordRules rules);
    }

    private static void refuses(Change change, String message) {
        PasswordRules rules = PasswordRules.defaults();
        change.apply(rules);
        try {
            rules.validate();
            fail("Accepted, though: " + message);
        }
        catch (GuacamoleClientException e) {
            assertEquals(message, e.getMessage());
        }
    }

}
