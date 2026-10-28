package io.github.ialzamil.guacamole.pam;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleSecurityException;
import org.apache.guacamole.environment.Environment;
import org.apache.guacamole.net.GuacamoleTunnel;
import org.apache.guacamole.net.auth.AbstractConnection;
import org.apache.guacamole.net.auth.AbstractUser;
import org.apache.guacamole.net.auth.AbstractUserContext;
import org.apache.guacamole.net.auth.AbstractUserGroup;
import org.apache.guacamole.net.auth.AuthenticationProvider;
import org.apache.guacamole.net.auth.Connection;
import org.apache.guacamole.net.auth.ConnectionRecord;
import org.apache.guacamole.net.auth.Directory;
import org.apache.guacamole.net.auth.GuacamoleProxyConfiguration;
import org.apache.guacamole.net.auth.Identifiable;
import org.apache.guacamole.net.auth.User;
import org.apache.guacamole.net.auth.UserContext;
import org.apache.guacamole.net.auth.UserGroup;
import org.apache.guacamole.net.auth.permission.SystemPermission;
import org.apache.guacamole.net.auth.permission.SystemPermissionSet;
import org.apache.guacamole.net.auth.simple.SimpleSystemPermissionSet;
import org.apache.guacamole.properties.GuacamoleProperty;
import org.apache.guacamole.protocol.GuacamoleClientInformation;
import org.apache.guacamole.protocol.GuacamoleConfiguration;
import org.apache.guacamole.protocols.ProtocolInfo;
import org.junit.Test;

import io.github.ialzamil.guacamole.pam.crypto.Secrets;
import io.github.ialzamil.guacamole.pam.db.ConnectionSecrets;
import io.github.ialzamil.guacamole.pam.db.PamDatabase;

/**
 * What the decorator refuses to anyone but administrators, wherever the
 * change comes from: password management and access requests of
 * connections, the account and host of managed connections, and who may
 * approve. Without a key, and so without the database.
 */
public class PamUserContextDecoratorTest {

    // ---- Stand-ins for Guacamole's side ----

    /**
     * Settings of the database, which is never used without a key.
     */
    private static final class TestEnvironment implements Environment {

        private final Map<String, String> properties = new HashMap<>();

        TestEnvironment() {
            properties.put("postgresql-database", "guacamole");
            properties.put("postgresql-username", "guacamole");
            properties.put("postgresql-password", "unused");
        }

        @Override
        public File getGuacamoleHome() {
            return new File(".");
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
        public <T> T getProperty(GuacamoleProperty<T> property) throws GuacamoleException {
            return property.parseValue(properties.get(property.getName()));
        }

        @Override
        public <T> T getProperty(GuacamoleProperty<T> property, T defaultValue) throws GuacamoleException {
            T value = getProperty(property);
            return value == null ? defaultValue : value;
        }

        @Override
        public <T> T getRequiredProperty(GuacamoleProperty<T> property) throws GuacamoleException {
            T value = getProperty(property);
            if (value == null)
                throw new GuacamoleException("Missing " + property.getName());
            return value;
        }

        @Override
        public GuacamoleProxyConfiguration getDefaultGuacamoleProxyConfiguration() {
            return null;
        }

    }

    private static final class MapDirectory<T extends Identifiable> implements Directory<T> {

        private final Map<String, T> objects = new LinkedHashMap<>();

        @Override
        public T get(String identifier) {
            return objects.get(identifier);
        }

        @Override
        public Collection<T> getAll(Collection<String> identifiers) {
            Collection<T> all = new ArrayList<>();
            for (String identifier : identifiers) {
                if (objects.containsKey(identifier))
                    all.add(objects.get(identifier));
            }
            return all;
        }

        @Override
        public Set<String> getIdentifiers() {
            return objects.keySet();
        }

        @Override
        public void add(T object) {
            for (int next = objects.size() + 1; object.getIdentifier() == null; next++) {
                if (!objects.containsKey(Integer.toString(next)))
                    object.setIdentifier(Integer.toString(next));
            }
            objects.put(object.getIdentifier(), object);
        }

        @Override
        public void update(T object) {
            objects.put(object.getIdentifier(), object);
        }

        @Override
        public void remove(String identifier) {
            objects.remove(identifier);
        }

    }

    private static final class TestConnection extends AbstractConnection {

        private Map<String, String> attributes = new HashMap<>();

        TestConnection(String identifier, Map<String, String> parameters, Map<String, String> attributes) {
            setIdentifier(identifier);
            setName("connection " + identifier);
            GuacamoleConfiguration configuration = new GuacamoleConfiguration();
            configuration.setProtocol("ssh");
            configuration.setParameters(parameters);
            setConfiguration(configuration);
            this.attributes = new HashMap<>(attributes);
        }

        /**
         * A copy, as the REST API makes one from what the editor sends.
         */
        TestConnection copy() {
            return new TestConnection(getIdentifier(), new HashMap<>(getConfiguration().getParameters()),
                    attributes);
        }

        @Override
        public Map<String, String> getAttributes() {
            return attributes;
        }

        @Override
        public void setAttributes(Map<String, String> attributes) {
            this.attributes = new HashMap<>(attributes);
        }

        @Override
        public java.util.Date getLastActive() {
            return null;
        }

        // Still declared by Guacamole's Connection, though deprecated
        @Override
        @Deprecated
        public java.util.List<? extends ConnectionRecord> getHistory() {
            return Collections.emptyList();
        }

        @Override
        public Set<String> getSharingProfileIdentifiers() {
            return Collections.emptySet();
        }

        @Override
        public int getActiveConnections() {
            return 0;
        }

        @Override
        public GuacamoleTunnel connect(GuacamoleClientInformation info, Map<String, String> tokens) {
            throw new UnsupportedOperationException();
        }

    }

    private static final class TestUser extends AbstractUser {

        private final boolean administrator;

        private Map<String, String> attributes = new HashMap<>();

        TestUser(String username, boolean administrator) {
            setIdentifier(username);
            this.administrator = administrator;
        }

        @Override
        public Map<String, String> getAttributes() {
            return attributes;
        }

        @Override
        public void setAttributes(Map<String, String> attributes) {
            this.attributes = new HashMap<>(attributes);
        }

        @Override
        public SystemPermissionSet getSystemPermissions() {
            return administrator ? new SimpleSystemPermissionSet(Collections.singleton(
                    new SystemPermission(SystemPermission.Type.ADMINISTER))) : new SimpleSystemPermissionSet();
        }

    }

    private static final class TestGroup extends AbstractUserGroup {

        private Map<String, String> attributes = new HashMap<>();

        TestGroup(String name) {
            setIdentifier(name);
        }

        @Override
        public Map<String, String> getAttributes() {
            return attributes;
        }

        @Override
        public void setAttributes(Map<String, String> attributes) {
            this.attributes = new HashMap<>(attributes);
        }

    }

    private static final class TestContext extends AbstractUserContext {

        private final User self;
        private final MapDirectory<Connection> connections = new MapDirectory<>();
        private final MapDirectory<User> users = new MapDirectory<>();
        private final MapDirectory<UserGroup> groups = new MapDirectory<>();

        TestContext(User self) {
            this.self = self;
        }

        @Override
        public User self() {
            return self;
        }

        @Override
        public AuthenticationProvider getAuthenticationProvider() {
            return null;
        }

        @Override
        public Directory<Connection> getConnectionDirectory() {
            return connections;
        }

        @Override
        public Directory<User> getUserDirectory() {
            return users;
        }

        @Override
        public Directory<UserGroup> getUserGroupDirectory() {
            return groups;
        }

    }

    // ---- Fixtures ----

    private static final Map<String, String> SSH = Collections.unmodifiableMap(new HashMap<String, String>() {{
        put("hostname", "host.example");
        put("port", "22");
        put("username", "root");
        put("font-size", "12");
    }});

    private final TestContext context;

    private final UserContext decorated;

    public PamUserContextDecoratorTest() throws GuacamoleException {
        this(false);
    }

    private PamUserContextDecoratorTest(boolean administrator) throws GuacamoleException {
        TestEnvironment environment = new TestEnvironment();
        context = new TestContext(new TestUser("someone", administrator));
        context.connections.add(new TestConnection("1", SSH, Collections.<String, String>emptyMap()));
        context.connections.add(new TestConnection("2", SSH,
                Collections.singletonMap(PamAttributes.PLATFORM, "7")));
        context.users.add(new TestUser("other", false));
        context.groups.add(new TestGroup("team"));
        decorated = new PamUserContextDecorator(context, null, null,
                new ConnectionSecrets(new PamDatabase(environment), Secrets.fromEnvironment(environment)));
    }

    private TestConnection stored(String identifier) {
        return (TestConnection) context.connections.get(identifier);
    }

    private static void assertRefused(String what, Action action) throws GuacamoleException {
        try {
            action.run();
            fail(what + " was not refused.");
        }
        catch (GuacamoleSecurityException e) {
            assertTrue(e.getMessage(), e.getMessage().startsWith("Only administrators"));
        }
    }

    @FunctionalInterface
    private interface Action {
        void run() throws GuacamoleException;
    }

    /**
     * The connection as the editor sends it back: a copy of what it read.
     */
    private TestConnection fromEditor(String identifier) {
        return stored(identifier).copy();
    }

    // ---- Connections ----

    @Test
    public void refusesPasswordManagementOfANewConnection() throws GuacamoleException {
        assertRefused("A new connection with a platform", () -> decorated.getConnectionDirectory().add(
                new TestConnection(null, SSH, Collections.singletonMap(PamAttributes.PLATFORM, "7"))));
        assertRefused("A new connection exempt from requests", () -> decorated.getConnectionDirectory().add(
                new TestConnection(null, SSH, Collections.singletonMap(PamAttributes.REQUEST_EXEMPT, "true"))));
        assertEquals(2, context.connections.getIdentifiers().size());
    }

    @Test
    public void acceptsANewConnectionWithoutPasswordManagement() throws GuacamoleException {
        decorated.getConnectionDirectory().add(new TestConnection(null, SSH, Collections.<String, String>emptyMap()));
        assertEquals(3, context.connections.getIdentifiers().size());
    }

    @Test
    public void refusesChangingAccessRequestsOrShowingThePassword() throws GuacamoleException {
        for (String attribute : new String[] { PamAttributes.REQUEST_EXEMPT, PamAttributes.REVEAL_PASSWORD,
                PamAttributes.APPROVALS_REQUIRED, PamAttributes.PLATFORM }) {
            TestConnection connection = fromEditor("1");
            connection.getAttributes().put(attribute, "true");
            assertRefused("Setting " + attribute, () -> decorated.getConnectionDirectory().update(connection));
            assertEquals(null, stored("1").getAttributes().get(attribute));
        }
    }

    @Test
    public void refusesRemovingAPlatform() throws GuacamoleException {
        TestConnection connection = fromEditor("2");
        connection.getAttributes().put(PamAttributes.PLATFORM, "");
        assertRefused("Removing the platform", () -> decorated.getConnectionDirectory().update(connection));
        assertEquals("7", stored("2").getAttributes().get(PamAttributes.PLATFORM));
    }

    @Test
    public void refusesChangingTheAccountOrHostOfAManagedConnection() throws GuacamoleException {
        for (String parameter : new String[] { "hostname", "port", "username", "domain", "gateway-hostname",
                "sftp-hostname", "enable-sftp", "dest-host", "host-key", "ignore-cert", "security",
                "password-regex" }) {
            TestConnection connection = fromEditor("2");
            connection.getConfiguration().setParameter(parameter, "changed");
            assertRefused("Changing " + parameter, () -> decorated.getConnectionDirectory().update(connection));
            assertEquals(SSH.get(parameter), stored("2").getConfiguration().getParameter(parameter));
        }
    }

    @Test
    public void refusesChangingTheProtocolOrGuacdOfAManagedConnection() throws GuacamoleException {

        for (String attribute : new String[] { "guacd-hostname", "guacd-port", "guacd-encryption" }) {
            TestConnection connection = fromEditor("2");
            connection.getAttributes().put(attribute, "changed");
            assertRefused("Changing " + attribute, () -> decorated.getConnectionDirectory().update(connection));
            assertEquals(null, stored("2").getAttributes().get(attribute));
        }

        TestConnection connection = fromEditor("2");
        connection.getConfiguration().setProtocol("telnet");
        assertRefused("Changing the protocol", () -> decorated.getConnectionDirectory().update(connection));
        assertEquals("ssh", stored("2").getConfiguration().getProtocol());

        // Of a connection that is not managed, as before
        TestConnection unmanaged = fromEditor("1");
        unmanaged.getAttributes().put("guacd-hostname", "other.example");
        unmanaged.getConfiguration().setProtocol("telnet");
        decorated.getConnectionDirectory().update(unmanaged);
        assertEquals("telnet", stored("1").getConfiguration().getProtocol());

    }

    @Test
    public void acceptsOtherChanges() throws GuacamoleException {

        // Any parameter of a connection that is not managed
        TestConnection unmanaged = fromEditor("1");
        unmanaged.getConfiguration().setParameter("hostname", "other.example");
        decorated.getConnectionDirectory().update(unmanaged);
        assertEquals("other.example", stored("1").getConfiguration().getParameter("hostname"));

        // Other parameters of a managed one
        TestConnection managed = fromEditor("2");
        managed.getConfiguration().setParameter("font-size", "14");
        decorated.getConnectionDirectory().update(managed);
        assertEquals("14", stored("2").getConfiguration().getParameter("font-size"));

    }

    @Test
    public void administratorsMayChangeAll() throws GuacamoleException {

        PamUserContextDecoratorTest admin = new PamUserContextDecoratorTest(true);

        admin.decorated.getConnectionDirectory().add(
                new TestConnection(null, SSH, Collections.singletonMap(PamAttributes.PLATFORM, "7")));
        assertEquals(3, admin.context.connections.getIdentifiers().size());

        TestConnection connection = admin.fromEditor("2");
        connection.getConfiguration().setParameter("hostname", "other.example");
        connection.getAttributes().put(PamAttributes.REVEAL_PASSWORD, "true");
        admin.decorated.getConnectionDirectory().update(connection);
        assertEquals("other.example", admin.stored("2").getConfiguration().getParameter("hostname"));
        assertEquals("true", admin.stored("2").getAttributes().get(PamAttributes.REVEAL_PASSWORD));

        TestUser user = new TestUser("other", false);
        user.setAttributes(Collections.singletonMap(PamAttributes.APPROVER, "true"));
        admin.decorated.getUserDirectory().update(user);
        assertEquals("true", admin.context.users.get("other").getAttributes().get(PamAttributes.APPROVER));

    }

    // ---- Who may approve ----

    @Test
    public void refusesChangingWhoMayApprove() throws GuacamoleException {

        // As the editor sends them: new objects, not the stored ones
        TestUser user = new TestUser("other", false);
        user.setAttributes(Collections.singletonMap(PamAttributes.APPROVER, "true"));
        assertRefused("Making a user an approver", () -> decorated.getUserDirectory().update(user));
        assertEquals(null, context.users.get("other").getAttributes().get(PamAttributes.APPROVER));

        TestGroup group = new TestGroup("team");
        group.setAttributes(Collections.singletonMap(PamAttributes.APPROVER_CONNECTIONS, "[\"2\"]"));
        assertRefused("Changing a group's connections to approve",
                () -> decorated.getUserGroupDirectory().update(group));

        TestUser created = new TestUser("new", false);
        created.setAttributes(Collections.singletonMap(PamAttributes.APPROVER, "true"));
        assertRefused("A new approver", () -> decorated.getUserDirectory().add(created));

    }

    @Test
    public void showsTheApprovalAttributesWhenUnset() throws GuacamoleException {
        Map<String, String> attributes = decorated.getUserDirectory().get("other").getAttributes();
        assertTrue(attributes.containsKey(PamAttributes.APPROVER));
        assertTrue(attributes.containsKey(PamAttributes.APPROVER_CONNECTIONS));
        assertTrue(attributes.containsKey(PamAttributes.APPROVER_CONNECTION_GROUPS));
    }

    @Test
    public void addsThePasswordManagementForms() {
        Collection<String> names = new ArrayList<>();
        decorated.getConnectionAttributes().forEach(form -> names.add(form.getName()));
        assertTrue(names.toString(), names.contains("pam-management"));
        assertTrue(names.toString(), names.contains("pam-checkout"));
    }

}
