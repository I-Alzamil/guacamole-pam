package org.apache.guacamole.pam.db;

import static org.junit.Assert.assertEquals;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.Test;

/**
 * The statements written differently on each database.
 */
public class SqlDialectTest {

    private static Map<String, String> values() {
        Map<String, String> values = new LinkedHashMap<>();
        values.put("id", "?");
        values.put("name", "?");
        return values;
    }

    private static final String UPDATES = "name = coalesce(t.name, EXCLUDED.name)";

    @Test
    public void upsertsOnPostgreSql() {
        assertEquals("INSERT INTO t (id, name) VALUES (?, ?) ON CONFLICT (id) DO UPDATE SET " + UPDATES,
                new PostgreSqlDialect().upsert("t", Collections.singletonList("id"), values(), UPDATES));
    }

    @Test
    public void upsertsOnMySql() {
        assertEquals("INSERT INTO t (id, name) VALUES (?, ?) ON DUPLICATE KEY UPDATE"
                + " name = coalesce(t.name, VALUES(name))",
                new MySqlDialect().upsert("t", Collections.singletonList("id"), values(), UPDATES));
    }

    @Test
    public void upsertsOnSqlServer() {
        assertEquals("MERGE INTO t WITH (HOLDLOCK) USING (VALUES (?, ?)) AS EXCLUDED (id, name)"
                + " ON t.id = EXCLUDED.id AND t.name = EXCLUDED.name"
                + " WHEN MATCHED THEN UPDATE SET " + UPDATES
                + " WHEN NOT MATCHED THEN INSERT (id, name) VALUES (EXCLUDED.id, EXCLUDED.name);",
                new SqlServerDialect().upsert("t", Arrays.asList("id", "name"), values(), UPDATES));
    }

    @Test
    public void listsNumbersAndParameters() {
        assertEquals("(NULL)", SqlDialect.in(Collections.<Integer>emptyList()));
        assertEquals("(1, 22)", SqlDialect.in(Arrays.asList(1, 22)));
        assertEquals("(NULL)", SqlDialect.parameters(0));
        assertEquals("(?, ?, ?)", SqlDialect.parameters(3));
    }

}
