package org.apache.guacamole.pam.db;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class SearchPatternTest {

    @Test
    public void matchesTheTermAnywhereIgnoringCase() {
        assertEquals("%bob%", SearchPattern.contains(" Bob "));
    }

    @Test
    public void escapesWildcardsAndTheEscapeCharacter() {
        assertEquals("%100!%!_off![x]!!\\%", SearchPattern.contains("100%_off[x]!\\"));
    }

}
