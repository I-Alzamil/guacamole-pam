package io.github.ialzamil.guacamole.pam.ha;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.net.GuacamoleTunnel;
import org.apache.guacamole.net.auth.ActiveConnection;
import org.apache.guacamole.net.auth.ActivityRecordSet;
import org.apache.guacamole.net.auth.Connection;
import org.apache.guacamole.net.auth.ConnectionGroup;
import org.apache.guacamole.net.auth.ConnectionRecord;
import org.apache.guacamole.net.auth.DecoratingDirectory;
import org.apache.guacamole.net.auth.DelegatingUserContext;
import org.apache.guacamole.net.auth.Directory;
import org.apache.guacamole.net.auth.UserContext;
import org.apache.guacamole.net.auth.permission.SystemPermission;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The context of a user of Guacamole's database authentication, whose
 * connections and connection groups count and limit their sessions on every
 * server, whose active connections are those of every server, and whose
 * connection history shows recordings kept on any server. Everything else,
 * including what other extensions decorating the same context do, is left
 * as it is: objects are unwrapped before being saved, so the extensions
 * this one wraps see their own.
 */
final class SyncedUserContext extends DelegatingUserContext {

    private static final Logger logger = LoggerFactory.getLogger(SyncedUserContext.class);

    private final SessionStore store;

    private final Config config;

    private final Recordings recordings;

    private final Status status;

    private final String remoteHost;

    /**
     * @param recordings
     *     Recordings of every server, or null if not shared.
     *
     * @param status
     *     The status of the servers, shown to administrators.
     *
     * @param remoteHost
     *     Where the user logged in from.
     */
    SyncedUserContext(UserContext context, SessionStore store, Config config, Recordings recordings,
            Status status, String remoteHost) {
        super(context);
        this.store = store;
        this.config = config;
        this.recordings = recordings;
        this.status = status;
        this.remoteHost = remoteHost;
    }

    /**
     * The user opening sessions, as Guacamole's database authentication
     * counts them for "max-connections-per-user".
     */
    String getUsername() {
        return self().getIdentifier();
    }

    String getRemoteHost() {
        return remoteHost;
    }

    /**
     * Whether the user administers the system, which Guacamole's database
     * authentication lets see and end every session.
     */
    boolean isPrivileged() throws GuacamoleException {
        return self().getEffectivePermissions().getSystemPermissions()
                .hasPermission(SystemPermission.Type.ADMINISTER);
    }

    /**
     * Where the session of a tunnel just opened runs, from the active
     * connection Guacamole lists for it, or else the record behind its
     * tunnel: the connection it picked, when through a balancing group, and
     * its guacd.
     *
     * @param connectionId
     *     The connection opened, or null if a balancing group was.
     */
    SessionStore.Details details(GuacamoleTunnel tunnel, String connectionId) {

        String tunnelId = tunnel.getUUID().toString();
        String host = remoteHost;
        try {
            ActiveConnection active = super.getActiveConnectionDirectory().get(tunnelId);
            if (active != null) {
                connectionId = active.getConnectionIdentifier();
                if (active.getRemoteHost() != null)
                    host = active.getRemoteHost();
            }
        }
        catch (GuacamoleException | RuntimeException e) {
            logger.debug("Unable to find the active connection of tunnel {}.", tunnelId, e);
        }
        if (connectionId == null)
            connectionId = Tunnels.recordedConnectionId(tunnel);

        return new SessionStore.Details(tunnelId, connectionId, host,
                Tunnels.guacd(store.getDatabase(), config, connectionId, Tunnels.guacdConnectionId(tunnel)));

    }

    /**
     * Connection history, with recordings kept on other servers.
     */
    ActivityRecordSet<ConnectionRecord> withRecordings(ActivityRecordSet<ConnectionRecord> history) {
        return recordings == null ? history : recordings.decorate(history);
    }

    @Override
    public Directory<Connection> getConnectionDirectory() throws GuacamoleException {
        return new DecoratingDirectory<Connection>(super.getConnectionDirectory()) {

            @Override
            protected Connection decorate(Connection object) {
                return new SyncedConnection(object, store, SyncedUserContext.this);
            }

            @Override
            protected Connection undecorate(Connection object) {
                return object instanceof SyncedConnection ? ((SyncedConnection) object).getUndecorated() : object;
            }

        };
    }

    @Override
    public Directory<ConnectionGroup> getConnectionGroupDirectory() throws GuacamoleException {
        return new DecoratingDirectory<ConnectionGroup>(super.getConnectionGroupDirectory()) {

            @Override
            protected ConnectionGroup decorate(ConnectionGroup object) {
                return new SyncedConnectionGroup(object, store, SyncedUserContext.this);
            }

            @Override
            protected ConnectionGroup undecorate(ConnectionGroup object) {
                return object instanceof SyncedConnectionGroup
                        ? ((SyncedConnectionGroup) object).getUndecorated() : object;
            }

        };
    }

    @Override
    public Directory<ActiveConnection> getActiveConnectionDirectory() throws GuacamoleException {
        return new SyncedActiveConnectionDirectory(super.getActiveConnectionDirectory(), this, store);
    }

    @Override
    public ActivityRecordSet<ConnectionRecord> getConnectionHistory() throws GuacamoleException {
        return withRecordings(super.getConnectionHistory());
    }

    /**
     * The status of the servers, for administrators. Guacamole's database
     * authentication has no resource of its own here.
     */
    @Override
    public Object getResource() throws GuacamoleException {
        return new StatusResource(status, store, this);
    }

}
