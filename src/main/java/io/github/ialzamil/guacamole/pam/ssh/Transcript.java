package io.github.ialzamil.guacamole.pam.ssh;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.function.UnaryOperator;

/**
 * The tail of a session's output, shown when a rotation fails, with the
 * passwords masked. Passwords are masked before the text is cut to length,
 * and once older output was dropped, the start of what is kept is dropped
 * as well (as long as the longest password), so no part of a password cut
 * in two can remain.
 */
final class Transcript {

    /**
     * Most characters shown.
     */
    static final int LIMIT = 2000;

    static final String MASK = "******";

    private final List<String> secrets = new ArrayList<>();

    /**
     * Length of the longest secret: how much of the start of the kept text
     * may hold part of a secret cut when older output was dropped.
     */
    private final int margin;

    private final StringBuilder text = new StringBuilder();

    private boolean trimmed = false;

    /**
     * @param secrets
     *     The values to mask; null or empty ones are ignored.
     */
    Transcript(Collection<String> secrets) {
        int longest = 0;
        for (String secret : secrets) {
            if (secret != null && !secret.isEmpty()) {
                this.secrets.add(secret);
                longest = Math.max(longest, secret.length());
            }
        }
        this.margin = longest;
    }

    void append(String output) {
        text.append(output);
        int keep = LIMIT + margin;
        if (text.length() > 2 * keep) {
            text.delete(0, text.length() - keep);
            trimmed = true;
        }
    }

    /**
     * The masked tail of the output, after the given clean-up (such as
     * removing terminal escapes).
     */
    String render(UnaryOperator<String> clean) {

        // The longest first: a secret within another, masked first, would
        // keep the other from being found
        String result = clean.apply(text.toString());
        List<String> longestFirst = new ArrayList<>(secrets);
        longestFirst.sort((a, b) -> b.length() - a.length());
        for (String secret : longestFirst)
            result = result.replace(secret, MASK);

        if (trimmed)
            result = result.substring(Math.min(margin, result.length()));

        if (result.length() > LIMIT)
            result = result.substring(result.length() - LIMIT);

        return result.trim();

    }

}
