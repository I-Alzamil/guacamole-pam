package io.github.ialzamil.guacamole.pam.ha;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleSecurityException;
import org.apache.guacamole.form.Field;
import org.apache.guacamole.net.GuacamoleTunnel;
import org.apache.guacamole.net.auth.AbstractActiveConnection;
import org.apache.guacamole.net.auth.ActiveConnection;
import org.apache.guacamole.net.auth.AtomicDirectoryOperation;
import org.apache.guacamole.net.auth.Directory;
import org.apache.guacamole.net.auth.SharingProfile;
import org.apache.guacamole.net.auth.credentials.CredentialsInfo;
import org.apache.guacamole.net.auth.credentials.UserCredentials;
import org.apache.guacamole.protocol.GuacamoleClientInformation;

/**
 * The active connections ("Active Sessions") of every server: those
 * Guacamole lists on this one, and those of the other servers, shown as
 * Guacamole shows its own, to whom it shows them: administrators see all,
 * other users those of connections they may use, with who opened them and
 * from where only for their own. Sessions of other servers can be ended,
 * joined and shared as Guacamole's own: ending one asks its server to end
 * it, and joining one, or opening its share link, connects to the guacd it
 * runs on.
 */
final class SyncedActiveConnectionDirectory implements Directory<ActiveConnection> {

    /**
     * The share links given, as Guacamole gives them.
     */
    private static final CredentialsInfo SHARE_KEY = new CredentialsInfo(Collections.<Field>singletonList(
            new Field("key", Field.Type.QUERY_PARAMETER)));

    private final Directory<ActiveConnection> local;

    private final SyncedUserContext context;

    private final SessionStore store;

    /**
     * Whether the user administers the system, and the connections they may
     * use, once asked.
     */
    private Boolean privileged;

    private Set<String> readable;

    SyncedActiveConnectionDirectory(Directory<ActiveConnection> local, SyncedUserContext context,
            SessionStore store) {
        this.local = local;
        this.context = context;
        this.store = store;
    }

    private boolean privileged() throws GuacamoleException {
        if (privileged == null)
            privileged = context.isPrivileged();
        return privileged;
    }

    private boolean visible(SessionRow row) throws GuacamoleException {
        if (privileged())
            return true;
        if (readable == null)
            readable = context.getConnectionDirectory().getIdentifiers();
        return readable.contains(row.connectionId);
    }

    /**
     * Whether the user may end, join and see the details of a session: if
     * an administrator, or it is theirs.
     */
    private boolean manages(SessionRow row) throws GuacamoleException {
        return privileged() || row.username.equals(context.getUsername());
    }

    /**
     * The sessions only this extension lists, the user may see, by
     * identifier.
     */
    private Map<String, SessionRow> rows(Set<String> listed) throws GuacamoleException {
        Map<String, SessionRow> rows = new HashMap<>();
        for (SessionRow row : store.unlisted()) {
            if (visible(row))
                rows.put(row.tunnelId, row);
        }
        for (SessionRow row : store.others()) {
            if (!listed.contains(row.tunnelId) && visible(row))
                rows.put(row.tunnelId, row);
        }
        return rows;
    }

    private Map<String, SessionRow> rows() throws GuacamoleException {
        return rows(local.getIdentifiers());
    }

    @Override
    public ActiveConnection get(String identifier) throws GuacamoleException {
        ActiveConnection connection = local.get(identifier);
        if (connection != null)
            return new LocalActiveConnection(connection);
        SessionRow row = rows().get(identifier);
        return row == null ? null : new OtherActiveConnection(row);
    }

    @Override
    public Collection<ActiveConnection> getAll(Collection<String> identifiers) throws GuacamoleException {
        Collection<ActiveConnection> connections = new ArrayList<>();
        Set<String> found = new HashSet<>();
        for (ActiveConnection connection : local.getAll(identifiers)) {
            connections.add(new LocalActiveConnection(connection));
            found.add(connection.getIdentifier());
        }
        Map<String, SessionRow> rows = rows();
        for (String identifier : identifiers) {
            SessionRow row = rows.get(identifier);
            if (row != null && !found.contains(identifier))
                connections.add(new OtherActiveConnection(row));
        }
        return connections;
    }

    @Override
    public Set<String> getIdentifiers() throws GuacamoleException {
        Set<String> listed = local.getIdentifiers();
        Set<String> identifiers = new HashSet<>(listed);
        identifiers.addAll(rows(listed).keySet());
        return identifiers;
    }

    @Override
    public void add(ActiveConnection object) throws GuacamoleException {
        local.add(object);
    }

    @Override
    public void update(ActiveConnection object) throws GuacamoleException {
        local.update(object instanceof LocalActiveConnection ? ((LocalActiveConnection) object).connection
                : object);
    }

    /**
     * Runs an operation as Guacamole's own directory runs it (atomically,
     * in a transaction of its database), on this directory, so its sessions
     * of other servers can be ended in it too.
     */
    @Override
    public void tryAtomically(AtomicDirectoryOperation<ActiveConnection> operation) throws GuacamoleException {
        local.tryAtomically((atomic, directory) -> operation.executeOperation(atomic,
                new SyncedActiveConnectionDirectory(directory, context, store)));
    }

    /**
     * Ends a session, as Guacamole ends its own: if the user administers
     * the system, or it is theirs.
     */
    @Override
    public void remove(String identifier) throws GuacamoleException {

        if (local.get(identifier) != null) {
            local.remove(identifier);
            return;
        }

        SessionRow row = rows().get(identifier);
        if (row == null)
            return;
        if (!manages(row))
            throw new GuacamoleSecurityException("Permission denied.");
        store.end(row.sessionId);

    }

    /**
     * An active connection Guacamole lists, whose share links are recorded
     * so every server opens them.
     */
    private final class LocalActiveConnection implements ActiveConnection {

        private final ActiveConnection connection;

        LocalActiveConnection(ActiveConnection connection) {
            this.connection = connection;
        }

        @Override
        public UserCredentials getSharingCredentials(String identifier) throws GuacamoleException {
            UserCredentials credentials = connection.getSharingCredentials(identifier);
            String key = credentials == null ? null : credentials.getValue("key");
            String sessionId = store.sessionOfTunnel(getIdentifier());
            if (key != null && sessionId != null)
                store.registerShare(sessionId, key, identifier);
            return credentials;
        }

        @Override
        public String getIdentifier() {
            return connection.getIdentifier();
        }

        @Override
        public void setIdentifier(String identifier) {
            connection.setIdentifier(identifier);
        }

        @Override
        public String getConnectionIdentifier() {
            return connection.getConnectionIdentifier();
        }

        @Override
        public void setConnectionIdentifier(String connnectionIdentifier) {
            connection.setConnectionIdentifier(connnectionIdentifier);
        }

        @Override
        public String getSharingProfileIdentifier() {
            return connection.getSharingProfileIdentifier();
        }

        @Override
        public void setSharingProfileIdentifier(String sharingProfileIdentifier) {
            connection.setSharingProfileIdentifier(sharingProfileIdentifier);
        }

        @Override
        public Date getStartDate() {
            return connection.getStartDate();
        }

        @Override
        public void setStartDate(Date startDate) {
            connection.setStartDate(startDate);
        }

        @Override
        public String getRemoteHost() {
            return connection.getRemoteHost();
        }

        @Override
        public void setRemoteHost(String remoteHost) {
            connection.setRemoteHost(remoteHost);
        }

        @Override
        public String getUsername() {
            return connection.getUsername();
        }

        @Override
        public void setUsername(String username) {
            connection.setUsername(username);
        }

        @Override
        public GuacamoleTunnel getTunnel() {
            return connection.getTunnel();
        }

        @Override
        public void setTunnel(GuacamoleTunnel tunnel) {
            connection.setTunnel(tunnel);
        }

        @Override
        public boolean isConnectable() {
            return connection.isConnectable();
        }

        @Override
        public GuacamoleTunnel connect(GuacamoleClientInformation info, Map<String, String> tokens)
                throws GuacamoleException {
            return connection.connect(info, tokens);
        }

        @Override
        public int getActiveConnections() {
            return connection.getActiveConnections();
        }

    }

    /**
     * A session only this extension lists: one of another server, or one of
     * this server joining a session of another.
     */
    private final class OtherActiveConnection extends AbstractActiveConnection {

        private final SessionRow row;

        private final boolean managed;

        OtherActiveConnection(SessionRow row) throws GuacamoleException {
            this.row = row;
            this.managed = manages(row);
            setIdentifier(row.tunnelId);
            setConnectionIdentifier(row.connectionId);
            setSharingProfileIdentifier(row.sharingProfileId);
            setStartDate(row.started);
            if (managed) {
                setUsername(row.username);
                setRemoteHost(row.remoteHost);
            }
        }

        @Override
        public boolean isConnectable() {
            return managed && row.joinable();
        }

        /**
         * Joins the session, sharing it fully, as Guacamole joins its own.
         */
        @Override
        public GuacamoleTunnel connect(GuacamoleClientInformation info, Map<String, String> tokens)
                throws GuacamoleException {
            if (!managed)
                throw new GuacamoleSecurityException("Permission denied.");
            return Joins.open(store, row, null, context.getUsername(), context.getRemoteHost(), info, tokens);
        }

        @Override
        public int getActiveConnections() {
            return 0;
        }

        /**
         * A share link of the session, with a sharing profile of its
         * connection the user may use, as Guacamole gives them.
         */
        @Override
        public UserCredentials getSharingCredentials(String identifier) throws GuacamoleException {
            SharingProfile profile = context.getSharingProfileDirectory().get(identifier);
            if (!managed || profile == null || !row.connectionId.equals(profile.getPrimaryConnectionIdentifier()))
                throw new GuacamoleSecurityException("Permission denied.");
            return new UserCredentials(SHARE_KEY, Collections.singletonMap("key",
                    store.share(row.sessionId, identifier)));
        }

    }

}
