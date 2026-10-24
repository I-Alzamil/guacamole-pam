package io.github.ialzamil.guacamole.pam.password;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

/**
 * Generates random passwords following the rules of a password policy: at
 * least the minimum of each kind of character, the rest drawn from every kind
 * allowed, in random order.
 */
public final class PasswordGenerator {

    private static final String LOWER = "abcdefghijklmnopqrstuvwxyz";
    private static final String UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String DIGITS = "0123456789";

    /**
     * Characters easily mistaken for others, left out on request.
     */
    private static final String AMBIGUOUS = "lIO01";

    private final SecureRandom random = new SecureRandom();

    /**
     * Generates a password following the given rules, which must be valid
     * (see {@link PasswordRules#validate}).
     */
    public String generate(PasswordRules rules) {

        String lower = rules.isLowercase() ? without(LOWER, rules) : "";
        String upper = rules.isUppercase() ? without(UPPER, rules) : "";
        String digits = rules.isDigits() ? without(DIGITS, rules) : "";
        String symbols = rules.isSymbols() ? rules.getSymbolSet() : "";
        String letters = lower + upper;
        String all = letters + digits + symbols;

        List<Character> password = new ArrayList<>(rules.getLength());
        pick(password, lower, rules.getMinLowercase());
        pick(password, upper, rules.getMinUppercase());
        pick(password, digits, rules.getMinDigits());
        pick(password, symbols, rules.getMinSymbols());

        // Starting with a letter needs one, even with no minimum of either
        if (rules.isStartWithLetter() && rules.getMinLowercase() + rules.getMinUppercase() == 0)
            pick(password, letters, 1);

        while (password.size() < rules.getLength())
            pick(password, all, 1);

        // Shuffle, so the characters of the minimums are anywhere
        for (int i = password.size() - 1; i > 0; i--) {
            int j = random.nextInt(i + 1);
            Character swap = password.get(i);
            password.set(i, password.get(j));
            password.set(j, swap);
        }

        // Then bring a letter to the front, which keeps the order random
        if (rules.isStartWithLetter() && letters.indexOf(password.get(0)) < 0) {
            List<Integer> positions = new ArrayList<>();
            for (int i = 1; i < password.size(); i++) {
                if (letters.indexOf(password.get(i)) >= 0)
                    positions.add(i);
            }
            int letter = positions.get(random.nextInt(positions.size()));
            Character swap = password.get(0);
            password.set(0, password.get(letter));
            password.set(letter, swap);
        }

        StringBuilder text = new StringBuilder(password.size());
        for (char c : password)
            text.append(c);
        return text.toString();

    }

    /**
     * About how many bits of randomness the passwords of the given rules
     * have: their length times the bits of each character, drawn from every
     * character allowed. Minimums and starting with a letter make it a
     * little less.
     */
    public static int strengthBits(PasswordRules rules) {
        int characters = (rules.isLowercase() ? without(LOWER, rules).length() : 0)
                + (rules.isUppercase() ? without(UPPER, rules).length() : 0)
                + (rules.isDigits() ? without(DIGITS, rules).length() : 0)
                + (rules.isSymbols() ? rules.getSymbolSet().length() : 0);
        return (int) Math.floor(rules.getLength() * Math.log(characters) / Math.log(2));
    }

    private static String without(String characters, PasswordRules rules) {
        if (!rules.isExcludeAmbiguous())
            return characters;
        StringBuilder kept = new StringBuilder();
        for (char c : characters.toCharArray()) {
            if (AMBIGUOUS.indexOf(c) < 0)
                kept.append(c);
        }
        return kept.toString();
    }

    private void pick(List<Character> password, String characters, int count) {
        for (int i = 0; i < count; i++)
            password.add(characters.charAt(random.nextInt(characters.length())));
    }

}
