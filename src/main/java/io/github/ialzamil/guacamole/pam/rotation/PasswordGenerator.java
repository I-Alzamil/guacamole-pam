package io.github.ialzamil.guacamole.pam.rotation;

import java.security.SecureRandom;

/**
 * Generates random passwords containing at least one lowercase letter,
 * uppercase letter, digit and symbol.
 */
public final class PasswordGenerator {

    public static final int DEFAULT_LENGTH = 24;
    public static final int MIN_LENGTH = 12;
    public static final int MAX_LENGTH = 128;

    private static final String LOWER = "abcdefghijkmnopqrstuvwxyz";
    private static final String UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ";
    private static final String DIGITS = "23456789";

    /**
     * Symbols with no special meaning to common shells or cmd.exe, so a
     * password stays intact even if a sequence places it on a command line.
     */
    private static final String SYMBOLS = "-_=+.,:@";

    private static final String[] CLASSES = { LOWER, UPPER, DIGITS, SYMBOLS };

    private static final String ALL = LOWER + UPPER + DIGITS + SYMBOLS;

    private final SecureRandom random = new SecureRandom();

    /**
     * Generates a password of the given length, clamped to
     * [MIN_LENGTH, MAX_LENGTH].
     */
    public String generate(int length) {

        length = Math.max(MIN_LENGTH, Math.min(MAX_LENGTH, length));
        char[] password = new char[length];

        for (int i = 0; i < CLASSES.length; i++)
            password[i] = pick(CLASSES[i]);

        for (int i = CLASSES.length; i < length; i++)
            password[i] = pick(ALL);

        // Shuffle so the guaranteed characters are not always first
        for (int i = length - 1; i > 0; i--) {
            int j = random.nextInt(i + 1);
            char swap = password[i];
            password[i] = password[j];
            password[j] = swap;
        }

        return new String(password);

    }

    private char pick(String characters) {
        return characters.charAt(random.nextInt(characters.length()));
    }

}
