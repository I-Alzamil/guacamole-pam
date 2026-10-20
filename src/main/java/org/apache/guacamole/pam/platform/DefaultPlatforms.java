package org.apache.guacamole.pam.platform;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * The platforms a fresh install starts with, and which can be restored:
 * "Unix", "macOS" and "Windows". They are kept in the format
 * of exported platforms ({@value #RESOURCE}), which also shows that format.
 */
final class DefaultPlatforms {

    static final String RESOURCE = "/platforms/defaults.json";

    private static final TypeReference<List<Platform>> PLATFORM_LIST = new TypeReference<List<Platform>>() { };

    private DefaultPlatforms() {
    }

    /**
     * Reads the default platforms, anew each time, as callers change them.
     */
    static List<Platform> read() {
        try (InputStream in = DefaultPlatforms.class.getResourceAsStream(RESOURCE)) {
            ObjectMapper json = new ObjectMapper();
            JsonNode file = json.readTree(in);
            return json.convertValue(file.get("platforms"), PLATFORM_LIST);
        }
        catch (IOException | RuntimeException e) {
            throw new IllegalStateException("Unable to read " + RESOURCE + ".", e);
        }
    }

}
