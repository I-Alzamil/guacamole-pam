package org.apache.guacamole.pam.ssh;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

import org.apache.guacamole.pam.ssh.SequenceScript.StepType;
import org.junit.Test;

public class SequenceScriptTest {

    @Test
    public void parsesSendsAndDirectives() {

        SequenceScript script = SequenceScript.parse(
                "# comment\n"
              + "\n"
              + "passwd <USER>  \r\n"
              + "@expect New password:\n"
              + "@timeout 30\n"
              + "<NEWPASS>\n"
              + "@regex (?i)updated\n"
              + "\\@literal\n"
              + "@send\n");

        assertTrue(script.getErrors().toString(), script.isValid());
        assertEquals(7, script.getSteps().size());

        assertEquals(StepType.SEND, script.getSteps().get(0).getType());
        assertEquals("passwd <USER>  ", script.getSteps().get(0).getValue());
        assertEquals(3, script.getSteps().get(0).getLine());

        assertEquals(StepType.EXPECT, script.getSteps().get(1).getType());
        assertEquals("New password:", script.getSteps().get(1).getValue());

        assertEquals(StepType.TIMEOUT, script.getSteps().get(2).getType());
        assertEquals("30", script.getSteps().get(2).getValue());

        assertTrue(script.getSteps().get(3).sendsNewPassword());
        assertEquals(StepType.REGEX, script.getSteps().get(4).getType());
        assertEquals("@literal", script.getSteps().get(5).getValue());
        assertEquals("", script.getSteps().get(6).getValue());

    }

    @Test
    public void reportsErrorsWithLineNumbers() {

        SequenceScript script = SequenceScript.parse(
                "@expect\n"
              + "@regex ([\n"
              + "@timeout forever\n"
              + "@wait 5\n"
              + "echo <NEWPASSWORD>\n");

        assertFalse(script.isValid());
        assertEquals(1, script.getErrors().get(0).getLine());
        assertEquals(2, script.getErrors().get(1).getLine());
        assertEquals(3, script.getErrors().get(2).getLine());
        assertEquals(4, script.getErrors().get(3).getLine());
        assertEquals(5, script.getErrors().get(4).getLine());

        // The missing <NEWPASS> is reported for the whole script
        assertEquals(0, script.getErrors().get(5).getLine());

    }

    @Test
    public void sendsLinesOfSpacesButSkipsEmptyLines() {

        SequenceScript script = SequenceScript.parse("<NEWPASS>\n\n   \n  indented\n");

        assertTrue(script.isValid());
        assertEquals(3, script.getSteps().size());
        assertEquals("   ", script.getSteps().get(1).getValue());
        assertEquals(3, script.getSteps().get(1).getLine());
        assertEquals("  indented", script.getSteps().get(2).getValue());

    }

    @Test
    public void requiresNewPassword() {
        assertFalse(SequenceScript.parse("passwd\n@expect assword:\n<OLDPASS>\n").isValid());
        assertTrue(SequenceScript.parse("<NEWPASS>").isValid());
    }

    @Test
    public void substitutesPlaceholders() {

        Map<String, String> values = new HashMap<>();
        values.put(SequenceScript.USER, "alice");
        values.put(SequenceScript.NEWPASS, "a$1.b");

        assertEquals("net user alice a$1.b", SequenceScript.substitute("net user <USER> <NEWPASS>", values, false));

        String regex = SequenceScript.substitute("for <USER>.*<NEWPASS>", values, true);
        assertTrue(Pattern.compile(regex).matcher("for alice is a$1.b").find());
        assertFalse(Pattern.compile(regex).matcher("for alice is aX1Xb").find());

    }

}
