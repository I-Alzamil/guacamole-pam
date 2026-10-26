package io.github.ialzamil.guacamole.pam.ha;

import java.util.Collections;
import java.util.Map;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.net.GuacamoleTunnel;
import org.apache.guacamole.net.auth.ActivityRecordSet;
import org.apache.guacamole.net.auth.Connection;
import org.apache.guacamole.net.auth.ConnectionRecord;
import org.apache.guacamole.net.auth.DelegatingConnection;
import org.apache.guacamole.protocol.GuacamoleClientInformation;

/**
 * A connection whose sessions are counted, and limited, on every server,
 * and recorded with where they run, so other servers list them, join them
 * and can end them.
 */
final class SyncedConnection extends DelegatingConnection {

    private final SessionStore store;

    private final SyncedUserContext context;

    SyncedConnection(Connection connection, SessionStore store, SyncedUserContext context) {
        super(connection);
        this.store = store;
        this.context = context;
    }

    Connection getUndecorated() {
        return getDelegateConnection();
    }

    private Target target() {
        return new Target(Target.Kind.CONNECTION, getIdentifier());
    }

    /**
     * The sessions of every server, or what the wrapped connection reports
     * if more: its own server's sessions, or what another extension counts
     * in its own way, such as users holding a connection that has no
     * sessions.
     */
    @Override
    public int getActiveConnections() {
        return Math.max(super.getActiveConnections(), store.count(target()));
    }

    @Override
    public ActivityRecordSet<ConnectionRecord> getConnectionHistory() throws GuacamoleException {
        return context.withRecordings(super.getConnectionHistory());
    }

    /**
     * Guacamole's deprecated way in, still overridden so it cannot bypass
     * {@link #connect(GuacamoleClientInformation, Map)}.
     */
    @Override
    @Deprecated
    public GuacamoleTunnel connect(GuacamoleClientInformation info) throws GuacamoleException {
        return connect(info, Collections.<String, String>emptyMap());
    }

    /**
     * Records the session, refused if over the connection's limits on every
     * server, then opens it. The wrapped connection is called directly:
     * going through DelegatingConnection would route through the
     * deprecated connect(info), which calls back here.
     */
    @Override
    public GuacamoleTunnel connect(GuacamoleClientInformation info, Map<String, String> tokens)
            throws GuacamoleException {

        String sessionId = store.open(target(), context.getUsername(),
                Limits.of(Target.Kind.CONNECTION, getAttributes(), store.getDefaults()));

        try {
            GuacamoleTunnel tunnel = getDelegateConnection().connect(info, tokens);
            SessionTunnel session = new SessionTunnel(tunnel, () -> store.close(sessionId));
            store.attach(sessionId, session, context.details(tunnel, getIdentifier()));
            return session;
        }
        catch (GuacamoleException | RuntimeException e) {
            store.close(sessionId);
            throw e;
        }

    }

}
