package org.apache.guacamole.pam.profile;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Parsed form of a sequence profile script.
 *
 * <pre>
 * # comment                 ignored, as are empty lines
 * passwd                    any other line is sent exactly as typed (spaces
 *                           included, even on a line of only spaces),
 *                           followed by Enter
 * &#64;expect New password:     wait until the output since the last send contains this text
 * &#64;regex (?i)updated        wait until the output since the last send matches this regex
 * &#64;timeout 20               seconds to wait in each following expect (default 10)
 * &#64;send text                send text explicitly; "&#64;send" alone sends just Enter
 * \&#64;literal                 a leading backslash sends the rest of the line as-is
 * </pre>
 *
 * Placeholders &lt;USER&gt;, &lt;HOST&gt;, &lt;OLDPASS&gt; and &lt;NEWPASS&gt;
 * are replaced in sent lines and expected text.
 */
public final class SequenceScript {

    public static final String USER = "USER";
    public static final String HOST = "HOST";
    public static final String OLDPASS = "OLDPASS";
    public static final String NEWPASS = "NEWPASS";

    public static final Set<String> PLACEHOLDERS = Collections.unmodifiableSet(
            new LinkedHashSet<>(Arrays.asList(USER, HOST, OLDPASS, NEWPASS)));

    public static final int DEFAULT_TIMEOUT = 10;

    public static final int MAX_TIMEOUT = 600;

    private static final Pattern PLACEHOLDER = Pattern.compile("<([A-Z_]+)>");

    public enum StepType { SEND, EXPECT, REGEX, TIMEOUT }

    /**
     * One instruction of the script.
     */
    public static final class Step {

        private final StepType type;
        private final String value;
        private final int line;

        Step(StepType type, String value, int line) {
            this.type = type;
            this.value = value;
            this.line = line;
        }

        public StepType getType() {
            return type;
        }

        /**
         * Text to send, text or regex to expect, or timeout in seconds,
         * with placeholders not yet substituted.
         */
        public String getValue() {
            return value;
        }

        public int getLine() {
            return line;
        }

        /**
         * Whether this step sends the new password.
         */
        public boolean sendsNewPassword() {
            return type == StepType.SEND && value.contains("<" + NEWPASS + ">");
        }

    }

    /**
     * A problem found while parsing, tied to a 1-based line number (0 for
     * problems with the script as a whole).
     */
    public static final class ParseError {

        private final int line;
        private final String message;

        ParseError(int line, String message) {
            this.line = line;
            this.message = message;
        }

        public int getLine() {
            return line;
        }

        public String getMessage() {
            return message;
        }

        @Override
        public String toString() {
            return line > 0 ? "Line " + line + ": " + message : message;
        }

    }

    private final List<Step> steps;

    private final List<ParseError> errors;

    private SequenceScript(List<Step> steps, List<ParseError> errors) {
        this.steps = Collections.unmodifiableList(steps);
        this.errors = Collections.unmodifiableList(errors);
    }

    public List<Step> getSteps() {
        return steps;
    }

    public List<ParseError> getErrors() {
        return errors;
    }

    public boolean isValid() {
        return errors.isEmpty();
    }

    public static SequenceScript parse(String script) {

        List<Step> steps = new ArrayList<>();
        List<ParseError> errors = new ArrayList<>();

        String[] lines = (script == null ? "" : script).split("\n", -1);
        for (int i = 0; i < lines.length; i++) {

            int number = i + 1;
            String line = lines[i].endsWith("\r")
                    ? lines[i].substring(0, lines[i].length() - 1) : lines[i];
            String trimmed = line.trim();

            // Only truly empty lines are skipped; a line of spaces is sent
            if (line.isEmpty() || trimmed.startsWith("#"))
                continue;

            if (trimmed.startsWith("\\")) {
                addStep(steps, errors, StepType.SEND, trimmed.substring(1), number);
                continue;
            }

            // Sent exactly as typed, spaces included
            if (!trimmed.startsWith("@")) {
                addStep(steps, errors, StepType.SEND, line, number);
                continue;
            }

            int space = trimmed.indexOf(' ');
            String directive = (space < 0 ? trimmed.substring(1) : trimmed.substring(1, space)).toLowerCase();
            String argument = space < 0 ? "" : trimmed.substring(space + 1).trim();

            switch (directive) {

                case "send":
                    addStep(steps, errors, StepType.SEND, argument, number);
                    break;

                case "expect":
                    if (argument.isEmpty())
                        errors.add(new ParseError(number, "@expect needs the text to wait for."));
                    else
                        addStep(steps, errors, StepType.EXPECT, argument, number);
                    break;

                case "regex":
                    if (argument.isEmpty()) {
                        errors.add(new ParseError(number, "@regex needs a regular expression."));
                        break;
                    }
                    try {
                        Pattern.compile(PLACEHOLDER.matcher(argument).replaceAll("x"));
                        addStep(steps, errors, StepType.REGEX, argument, number);
                    }
                    catch (PatternSyntaxException e) {
                        errors.add(new ParseError(number, "Invalid regular expression: " + e.getDescription()));
                    }
                    break;

                case "timeout":
                    try {
                        int seconds = Integer.parseInt(argument);
                        if (seconds < 1 || seconds > MAX_TIMEOUT)
                            throw new NumberFormatException();
                        steps.add(new Step(StepType.TIMEOUT, Integer.toString(seconds), number));
                    }
                    catch (NumberFormatException e) {
                        errors.add(new ParseError(number, "@timeout needs a number of seconds between 1 and " + MAX_TIMEOUT + "."));
                    }
                    break;

                default:
                    errors.add(new ParseError(number, "Unknown directive @" + directive
                            + ". Use @expect, @regex, @timeout or @send, or start the line with \\ to send it as-is."));

            }

        }

        boolean sendsNewPassword = false;
        for (Step step : steps)
            sendsNewPassword |= step.sendsNewPassword();

        if (!sendsNewPassword)
            errors.add(new ParseError(0, "The sequence never sends <NEWPASS>, so it cannot change the password."));

        return new SequenceScript(steps, errors);

    }

    private static void addStep(List<Step> steps, List<ParseError> errors,
            StepType type, String value, int line) {

        Matcher matcher = PLACEHOLDER.matcher(value);
        while (matcher.find()) {
            if (!PLACEHOLDERS.contains(matcher.group(1)))
                errors.add(new ParseError(line, "Unknown placeholder <" + matcher.group(1)
                        + ">. Available: <USER>, <HOST>, <OLDPASS>, <NEWPASS>."));
        }

        steps.add(new Step(type, value, line));

    }

    /**
     * Replaces placeholders in the given text. Values are inserted literally,
     * or quoted when the text is a regular expression.
     */
    public static String substitute(String text, Map<String, String> values, boolean regex) {

        Matcher matcher = PLACEHOLDER.matcher(text);
        StringBuffer result = new StringBuffer();

        while (matcher.find()) {
            String value = values.get(matcher.group(1));
            if (value == null)
                value = "";
            matcher.appendReplacement(result, Matcher.quoteReplacement(regex ? Pattern.quote(value) : value));
        }

        matcher.appendTail(result);
        return result.toString();

    }

}
