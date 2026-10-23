package io.github.ialzamil.guacamole.pam.crypto;

import java.util.Map;
import java.util.TreeMap;

/**
 * What a run of {@link SecretMigration} did: how many values it changed, and
 * which it could not decrypt, by key id.
 */
public final class MigrationReport {

    private int changed = 0;

    private final Map<String, Integer> unreadable = new TreeMap<>();

    public void changed(int count) {
        changed += count;
    }

    /**
     * Counts a value left as it is because it cannot be decrypted here.
     */
    public void unreadable(String value) {
        String keyId = SecretCipher.keyIdOf(value);
        String key = keyId == null ? "?" : keyId;
        unreadable.put(key, unreadable.getOrDefault(key, 0) + 1);
    }

    public int getChanged() {
        return changed;
    }

    /**
     * Values that cannot be decrypted here, by the id of their key.
     */
    public Map<String, Integer> getUnreadable() {
        return unreadable;
    }

}
