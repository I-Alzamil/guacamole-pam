package org.apache.guacamole.pam;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;

import org.junit.Test;

public class ValuesTest {

    @Test
    public void trimsNamesButNotPasswords() {
        assertEquals("host", Values.trimToNull("  host "));
        assertNull(Values.trimToNull("   "));
        assertNull(Values.trimToNull(null));
        assertEquals("  pw ", Values.emptyToNull("  pw "));
        assertEquals(" ", Values.emptyToNull(" "));
        assertNull(Values.emptyToNull(""));
    }

    @Test
    public void keepsLogValuesOnOneLine() {
        assertEquals("evil User \"x\" approved", Values.forLog("evil\r\nUser \"x\" approved"));
        assertEquals("a b c", Values.forLog("a\u2028b\u0000c"));
        assertNull(Values.forLog(null));
    }

    @Test
    public void readsIdentifiers() {
        assertEquals(Integer.valueOf(17), Values.parseId(" 17 "));
        assertNull(Values.parseId("17a"));
        assertNull(Values.parseId(""));
        assertNull(Values.parseId(null));
    }

    @Test
    public void readsPorts() {
        assertEquals(Integer.valueOf(22), Values.toPort("22"));
        assertNull(Values.toPort("0"));
        assertNull(Values.toPort("65536"));
        assertNull(Values.toPort("ssh"));
        assertEquals(5986, Values.parsePort(" ", 5986));
        assertEquals(1636, Values.parsePort("1636", 5986));
        try {
            Values.parsePort("70000", 5986);
            fail("Accepted port 70000.");
        }
        catch (IllegalArgumentException e) {
            assertEquals("Invalid port: 70000", e.getMessage());
        }
    }

}
