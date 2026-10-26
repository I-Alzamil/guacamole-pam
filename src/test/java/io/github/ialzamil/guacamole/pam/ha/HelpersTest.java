package io.github.ialzamil.guacamole.pam.ha;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

/**
 * The SQL helpers, and which guacd host names are this server's own.
 */
public class HelpersTest {

    @Test
    public void hashesSecrets() {
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", Sql.sha256("abc"));
    }

    @Test
    public void splitsValuesForIn() {
        List<Integer> values = new ArrayList<>();
        for (int i = 0; i < 2 * Sql.MAX_IN + 1; i++)
            values.add(i);
        List<List<Integer>> chunks = Sql.chunks(values);
        assertEquals(3, chunks.size());
        assertEquals(Sql.MAX_IN, chunks.get(0).size());
        assertEquals(1, chunks.get(2).size());
        assertTrue(Sql.chunks(new ArrayList<Integer>()).isEmpty());
        assertEquals("?, ?, ?", Sql.marks(3));
    }

    @Test
    public void readsIdentifiers() {
        assertEquals(Integer.valueOf(12), Sql.id("12"));
        assertNull(Sql.id("ROOT"));
        assertNull(Sql.id(null));
    }

    @Test
    public void findsLocalHosts() {
        for (String host : new String[] { "localhost", "LOCALHOST ", "127.0.0.1", "127.1.2.3", "::1", "[::1]",
                "0:0:0:0:0:0:0:1", "0.0.0.0" })
            assertTrue(host, Tunnels.isLocal(host));
        for (String host : new String[] { "guacd", "10.0.0.1", "localhost.example.com", "::2" })
            assertFalse(host, Tunnels.isLocal(host));
    }

}
