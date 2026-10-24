package io.github.ialzamil.guacamole.pam.password;

import java.util.LinkedHashSet;
import java.util.Set;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import org.apache.guacamole.GuacamoleClientException;

/**
 * What passwords of a password policy are made of: their length, which kinds
 * of characters they may have and at least how many of each, which symbols,
 * and whether to avoid characters easily mistaken for others and to start
 * with a letter, as each target system requires.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public final class PasswordRules {

    public static final int MIN_LENGTH = 4;
    public static final int MAX_LENGTH = 128;

    /**
     * Symbols with no special meaning to common shells or cmd.exe, so a
     * password stays intact even if a sequence places it on a command line.
     */
    public static final String SAFE_SYMBOLS = "-_=+.,:@";

    private int length = 24;
    private boolean lowercase = true;
    private int minLowercase = 1;
    private boolean uppercase = true;
    private int minUppercase = 1;
    private boolean digits = true;
    private int minDigits = 1;
    private boolean symbols = true;
    private int minSymbols = 1;
    private String symbolSet = SAFE_SYMBOLS;
    private boolean excludeAmbiguous = true;
    private boolean startWithLetter = false;

    /**
     * The rules of passwords without a password policy: 24 characters, with
     * every kind of character, at least one of each, the safe symbols, and
     * no characters easily mistaken for others.
     */
    public static PasswordRules defaults() {
        return new PasswordRules();
    }

    /**
     * Checks the rules can make passwords, and normalizes the symbols (each
     * once, in the order given).
     *
     * @throws GuacamoleClientException
     *     If they cannot, saying why.
     */
    public PasswordRules validate() throws GuacamoleClientException {

        if (length < MIN_LENGTH || length > MAX_LENGTH)
            throw new GuacamoleClientException("The length must be from " + MIN_LENGTH + " to " + MAX_LENGTH + ".");

        if (!lowercase && !uppercase && !digits && !symbols)
            throw new GuacamoleClientException("Allow at least one kind of character.");

        if (minLowercase < 0 || minUppercase < 0 || minDigits < 0 || minSymbols < 0)
            throw new GuacamoleClientException("Minimums cannot be negative.");

        // A kind not allowed has no minimum
        if (!lowercase) minLowercase = 0;
        if (!uppercase) minUppercase = 0;
        if (!digits) minDigits = 0;
        if (!symbols) minSymbols = 0;

        if (symbols) {
            Set<Character> unique = new LinkedHashSet<>();
            for (char c : (symbolSet == null ? "" : symbolSet).toCharArray()) {
                if (c < 33 || c > 126 || Character.isLetterOrDigit(c))
                    throw new GuacamoleClientException("Symbols must be printable ASCII characters other than"
                            + " letters, digits and spaces.");
                unique.add(c);
            }
            if (unique.isEmpty())
                throw new GuacamoleClientException("Give the symbols to use, or do not allow symbols.");
            StringBuilder normalized = new StringBuilder();
            for (char c : unique)
                normalized.append(c);
            symbolSet = normalized.toString();
        }
        else
            symbolSet = "";

        if (startWithLetter && !lowercase && !uppercase)
            throw new GuacamoleClientException("Passwords cannot start with a letter without letters allowed.");

        int minimums = minLowercase + minUppercase + minDigits + minSymbols
                + (startWithLetter && minLowercase + minUppercase == 0 ? 1 : 0);
        if (minimums > length)
            throw new GuacamoleClientException("The minimums add up to " + minimums + " characters, more than the"
                    + " length of " + length + ".");

        return this;

    }

    public int getLength() {
        return length;
    }

    public void setLength(int length) {
        this.length = length;
    }

    public boolean isLowercase() {
        return lowercase;
    }

    public void setLowercase(boolean lowercase) {
        this.lowercase = lowercase;
    }

    public int getMinLowercase() {
        return minLowercase;
    }

    public void setMinLowercase(int minLowercase) {
        this.minLowercase = minLowercase;
    }

    public boolean isUppercase() {
        return uppercase;
    }

    public void setUppercase(boolean uppercase) {
        this.uppercase = uppercase;
    }

    public int getMinUppercase() {
        return minUppercase;
    }

    public void setMinUppercase(int minUppercase) {
        this.minUppercase = minUppercase;
    }

    public boolean isDigits() {
        return digits;
    }

    public void setDigits(boolean digits) {
        this.digits = digits;
    }

    public int getMinDigits() {
        return minDigits;
    }

    public void setMinDigits(int minDigits) {
        this.minDigits = minDigits;
    }

    public boolean isSymbols() {
        return symbols;
    }

    public void setSymbols(boolean symbols) {
        this.symbols = symbols;
    }

    public int getMinSymbols() {
        return minSymbols;
    }

    public void setMinSymbols(int minSymbols) {
        this.minSymbols = minSymbols;
    }

    /**
     * The symbols passwords may contain, if symbols are allowed.
     */
    public String getSymbolSet() {
        return symbolSet;
    }

    public void setSymbolSet(String symbolSet) {
        this.symbolSet = symbolSet;
    }

    /**
     * Whether characters easily mistaken for others (l, I, O, 0, 1) are left
     * out.
     */
    public boolean isExcludeAmbiguous() {
        return excludeAmbiguous;
    }

    public void setExcludeAmbiguous(boolean excludeAmbiguous) {
        this.excludeAmbiguous = excludeAmbiguous;
    }

    public boolean isStartWithLetter() {
        return startWithLetter;
    }

    public void setStartWithLetter(boolean startWithLetter) {
        this.startWithLetter = startWithLetter;
    }

}
