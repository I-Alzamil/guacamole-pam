package io.github.ialzamil.guacamole.pam.ssh;

import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

/**
 * Public keys of SSH certificate authorities, whose host certificates are
 * trusted: one per line, as in the CA's ".pub" file ("ssh-ed25519 AAAA...
 * comment"), or as a known_hosts "@cert-authority" line, whose host pattern
 * is then ignored (a certificate must name the host it is reached at).
 */
public final class SshAuthorities {

    private SshAuthorities() {
    }

    /**
     * The keys of the given lines, empty if there are none.
     *
     * @throws IllegalArgumentException
     *     If a line holds no valid public key.
     */
    public static List<byte[]> parse(String lines) {

        if (lines == null || lines.trim().isEmpty())
            return Collections.emptyList();

        List<byte[]> keys = new ArrayList<>();
        int number = 0;
        for (String line : lines.split("\\r?\\n")) {

            number++;
            String trimmed = line.trim();
            if (trimmed.isEmpty() || trimmed.startsWith("#"))
                continue;

            String[] fields = trimmed.split("\\s+");
            int first = fields[0].equals("@cert-authority") ? 2 : 0;
            if (fields.length < first + 2)
                throw new IllegalArgumentException("SSH CA key line " + number + " is not a public key"
                        + " (expected \"type base64 [comment]\").");

            byte[] key;
            try {
                key = Base64.getDecoder().decode(fields[first + 1]);
            }
            catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("SSH CA key line " + number + " has an invalid key.");
            }
            if (!fields[first].equals(PinnedHostKeyRepository.type(key)))
                throw new IllegalArgumentException("SSH CA key line " + number + " is not a " + fields[first]
                        + " key.");
            if (fields[first].contains("-cert-"))
                throw new IllegalArgumentException("SSH CA key line " + number + " is a certificate: give the"
                        + " CA's own public key.");
            keys.add(key);

        }
        return keys;

    }

}
