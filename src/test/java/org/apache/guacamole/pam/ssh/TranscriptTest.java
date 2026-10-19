package org.apache.guacamole.pam.ssh;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.function.UnaryOperator;

import org.junit.Test;

public class TranscriptTest {

    private static final String OLD = "OldSecretValue42";
    private static final String NEW = "NewSecretValueLonger77";

    private static final UnaryOperator<String> NO_CLEANUP = UnaryOperator.identity();

    @Test
    public void masksBothPasswords() {
        Transcript transcript = new Transcript(Arrays.asList(OLD, NEW));
        transcript.append("$ passwd\nCurrent: " + OLD + "\nNew: " + NEW + "\nRetype: " + NEW + "\nok\n");
        String text = transcript.render(NO_CLEANUP);
        assertFalse(text.contains(OLD));
        assertFalse(text.contains(NEW));
        assertTrue(text.contains("Current: " + Transcript.MASK));
        assertTrue(text.endsWith("ok"));
    }

    @Test
    public void ignoresMissingPasswords() {
        Transcript transcript = new Transcript(Arrays.asList(null, "", NEW));
        transcript.append("value " + NEW);
        assertEquals("value " + Transcript.MASK, transcript.render(NO_CLEANUP));
    }

    @Test
    public void keepsOnlyTheTail() {
        Transcript transcript = new Transcript(Arrays.asList(OLD, NEW));
        StringBuilder all = new StringBuilder();
        for (int i = 0; i < 2000; i++)
            all.append("line ").append(i).append('\n');
        transcript.append(all.toString());
        String text = transcript.render(NO_CLEANUP);
        assertTrue(text.length() <= Transcript.LIMIT);
        assertTrue(text.endsWith("line 1999"));
    }

    /**
     * Whatever output surrounds the passwords, and however it arrives, no
     * character of them survives, including when the tail starts inside one
     * (which the output after them decides): the output is otherwise made
     * only of characters no password contains.
     */
    @Test
    public void neverShowsPartOfAPasswordCutWhenOutputIsDropped() {
        for (int before : new int[] { 0, 1000, 4100, 9000 }) {
            for (int after = 1950; after <= 2050; after++) {
                for (int chunk : new int[] { 1, 7, 512, 100000 }) {

                    Transcript transcript = new Transcript(Arrays.asList(OLD, NEW));
                    String output = filler(before) + NEW + "......." + OLD + filler(after);
                    for (int i = 0; i < output.length(); i += chunk)
                        transcript.append(output.substring(i, Math.min(output.length(), i + chunk)));

                    String text = transcript.render(NO_CLEANUP);
                    assertFalse("before=" + before + " after=" + after + " chunk=" + chunk + ": " + text,
                            text.replace(Transcript.MASK, "").matches("(?s).*[A-Za-z0-9].*"));
                    assertTrue(text.length() <= Transcript.LIMIT);

                }
            }
        }
    }

    private static String filler(int length) {
        StringBuilder filler = new StringBuilder();
        for (int i = 0; i < length; i++)
            filler.append(i % 80 == 79 ? '\n' : '.');
        return filler.toString();
    }

    @Test
    public void appliesTheCleanupBeforeMasking() {
        Transcript transcript = new Transcript(Arrays.asList(NEW));
        // A terminal escape in the middle of the echoed password
        transcript.append("New: NewSecret\u001B[0mValueLonger77\n");
        String text = transcript.render(s -> s.replace("\u001B[0m", ""));
        assertEquals("New: " + Transcript.MASK, text);
    }

}
