package org.apache.guacamole.pam.ssh;

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
 * &#64;case (?i)current         starts a choice: waits until the output since the
 * ...                       last send matches the regex of one of its cases,
 * &#64;case (?i)new             then runs the lines of the case matching earliest
 * ...                       (the first written, if several match there) and
 * &#64;end                      continues after &#64;end
 * &#64;fail text                ends the script, reporting this text as the problem
 * </pre>
 *
 * Choices cannot be nested, and every way through the script must send
 * &lt;NEWPASS&gt;, unless it fails on purpose.
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

    public enum StepType { SEND, EXPECT, REGEX, TIMEOUT, CASE, END, FAIL }

    /**
     * The cases of a choice, as indexes of their steps, and the index of
     * its END step.
     */
    public static final class Choice {

        private final List<Integer> cases = new ArrayList<>();
        private int end = -1;

        public List<Integer> getCases() {
            return Collections.unmodifiableList(cases);
        }

        public int getEnd() {
            return end;
        }

    }

    /**
     * One instruction of the script.
     */
    public static final class Step {

        private final StepType type;
        private final String value;
        private final int line;
        private Choice choice;

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
         * The choice a CASE or END step belongs to, or null.
         */
        public Choice getChoice() {
            return choice;
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
        Choice open = null;
        int openLine = 0;

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

                case "case":
                    if (argument.isEmpty()) {
                        errors.add(new ParseError(number, "@case needs a regular expression."));
                        break;
                    }
                    try {
                        Pattern.compile(PLACEHOLDER.matcher(argument).replaceAll("x"));
                    }
                    catch (PatternSyntaxException e) {
                        errors.add(new ParseError(number, "Invalid regular expression: " + e.getDescription()));
                        break;
                    }
                    if (open == null) {
                        open = new Choice();
                        openLine = number;
                    }
                    open.cases.add(steps.size());
                    addStep(steps, errors, StepType.CASE, argument, number);
                    steps.get(steps.size() - 1).choice = open;
                    break;

                case "end":
                    if (open == null) {
                        errors.add(new ParseError(number, "@end without @case before it."));
                        break;
                    }
                    open.end = steps.size();
                    steps.add(new Step(StepType.END, "", number));
                    steps.get(steps.size() - 1).choice = open;
                    open = null;
                    break;

                case "fail":
                    // Not substituted: the text is shown as is, never with a password
                    if (argument.isEmpty())
                        errors.add(new ParseError(number, "@fail needs the problem to report."));
                    else
                        steps.add(new Step(StepType.FAIL, argument, number));
                    break;

                default:
                    errors.add(new ParseError(number, "Unknown directive @" + directive
                            + ". Use @expect, @regex, @timeout, @send, @case, @end or @fail, or start the line"
                            + " with \\ to send it as-is."));

            }

        }

        if (open != null) {
            errors.add(new ParseError(openLine, "@case without @end after it."));
            return new SequenceScript(steps, errors);
        }

        if (!alwaysSendsNewPassword(steps)) {
            Step fail = firstFailOutsideChoices(steps);
            if (fail != null)
                errors.add(new ParseError(fail.line, "@fail outside a choice, before <NEWPASS> is sent,"
                        + " stops every rotation."));
            else
                errors.add(new ParseError(0, steps.stream().anyMatch(Step::sendsNewPassword)
                        ? "One of the cases never sends <NEWPASS>, nor do the lines outside the choices,"
                                + " so the password would not change that way."
                        : "The sequence never sends <NEWPASS>, so it cannot change the password."));
        }

        return new SequenceScript(steps, errors);

    }

    /**
     * Whether every way through the steps sends the new password, or fails
     * on purpose: a line outside the choices sends it (before any @fail
     * there), or every case of one choice sends it or fails.
     */
    private static boolean alwaysSendsNewPassword(List<Step> steps) {

        for (int i = 0; i < steps.size(); i++) {

            Step step = steps.get(i);
            if (step.type == StepType.FAIL)
                return false;
            if (step.type != StepType.CASE) {
                if (step.sendsNewPassword())
                    return true;
                continue;
            }

            // Every case of this choice, up to the next case or the end
            Choice choice = step.choice;
            boolean everyCase = true;
            for (int c = 0; c < choice.cases.size(); c++) {
                int next = c + 1 < choice.cases.size() ? choice.cases.get(c + 1) : choice.end;
                boolean sends = false;
                for (int j = choice.cases.get(c) + 1; j < next; j++)
                    sends |= steps.get(j).sendsNewPassword() || steps.get(j).type == StepType.FAIL;
                everyCase &= sends;
            }
            if (everyCase)
                return true;
            i = choice.end;

        }

        return false;

    }

    private static Step firstFailOutsideChoices(List<Step> steps) {
        boolean inChoice = false;
        for (Step step : steps) {
            if (step.type == StepType.CASE)
                inChoice = true;
            else if (step.type == StepType.END)
                inChoice = false;
            else if (step.type == StepType.FAIL && !inChoice)
                return step;
        }
        return null;
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
