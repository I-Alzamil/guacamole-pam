package org.apache.guacamole.pam.db;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class SearchPatternTest {

    @Test
    public void matchesTheTermAnywhere() {
        assertEquals("%bob%", SearchPattern.contains(" bob "));
    }

    @Test
    public void escapesWildcardsAndTheEscapeCharacter() {
        assertEquals("%100\\%\\_off\\\\%", SearchPattern.contains("100%_off\\"));
    }

}
