package io.github.ialzamil.guacamole.pam.ha;

import java.io.File;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleServerException;
import org.apache.guacamole.environment.Environment;
import org.apache.guacamole.net.auth.GuacamoleProxyConfiguration;
import org.apache.guacamole.properties.GuacamoleProperty;
import org.apache.guacamole.protocols.ProtocolInfo;

/**
 * guacamole.properties as given, for tests.
 */
final class TestEnvironment implements Environment {

    private final Map<String, String> properties = new HashMap<>();

    TestEnvironment(String... namesAndValues) {
        for (int i = 0; i + 1 < namesAndValues.length; i += 2)
            properties.put(namesAndValues[i], namesAndValues[i + 1]);
    }

    @Override
    public <Type> Type getProperty(GuacamoleProperty<Type> property) throws GuacamoleException {
        return property.parseValue(properties.get(property.getName()));
    }

    @Override
    public <Type> Type getProperty(GuacamoleProperty<Type> property, Type defaultValue) throws GuacamoleException {
        Type value = getProperty(property);
        return value == null ? defaultValue : value;
    }

    @Override
    public <Type> Type getRequiredProperty(GuacamoleProperty<Type> property) throws GuacamoleException {
        Type value = getProperty(property);
        if (value == null)
            throw new GuacamoleServerException("Missing " + property.getName());
        return value;
    }

    private File home = new File(".");

    /**
     * Sets GUACAMOLE_HOME.
     */
    TestEnvironment home(File home) {
        this.home = home;
        return this;
    }

    @Override
    public File getGuacamoleHome() {
        return home;
    }

    @Override
    public Map<String, ProtocolInfo> getProtocols() {
        return Collections.emptyMap();
    }

    @Override
    public ProtocolInfo getProtocol(String name) {
        return null;
    }

    @Override
    public GuacamoleProxyConfiguration getDefaultGuacamoleProxyConfiguration() {
        return null;
    }

}
