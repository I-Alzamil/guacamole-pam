package io.github.ialzamil.guacamole.pam.ha;

import java.util.Collections;
import java.util.Map;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.net.GuacamoleTunnel;
import org.apache.guacamole.net.auth.ConnectionGroup;
import org.apache.guacamole.net.auth.DelegatingConnectionGroup;
import org.apache.guacamole.protocol.GuacamoleClientInformation;

/**
 * A connection group whose sessions, when it balances, are counted and
 * limited on every server, and recorded with the connection Guacamole
 * picked, which other servers then count as in use too. Which connection
 * Guacamole picks, and the limits of that connection, are still decided by
 * each server alone, from its own sessions: Guacamole's database
 * authentication picks it with nothing an extension can change.
 */
final class SyncedConnectionGroup extends DelegatingConnectionGroup {

    private final SessionStore store;

    private final SyncedUserContext context;

    SyncedConnectionGroup(ConnectionGroup group, SessionStore store, SyncedUserContext context) {
        super(group);
        this.store = store;
        this.context = context;
    }

    ConnectionGroup getUndecorated() {
        return getDelegateConnectionGroup();
    }

    private Target target() {
        return new Target(Target.Kind.CONNECTION_GROUP, getIdentifier());
    }

    /**
     * The sessions through this group of every server, or what the wrapped
     * group reports if more.
     */
    @Override
    public int getActiveConnections() {
        return Math.max(super.getActiveConnections(), store.count(target()));
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
     * Records the session of a balancing group, refused if over the group's
     * limits on every server, then opens it. Other groups have no session
     * of their own: the wrapped group refuses them.
     */
    @Override
    public GuacamoleTunnel connect(GuacamoleClientInformation info, Map<String, String> tokens)
            throws GuacamoleException {

        if (getType() != Type.BALANCING)
            return getDelegateConnectionGroup().connect(info, tokens);

        String sessionId = store.open(target(), context.getUsername(),
                Limits.of(Target.Kind.CONNECTION_GROUP, getAttributes(), store.getDefaults()));

        try {
            GuacamoleTunnel tunnel = getDelegateConnectionGroup().connect(info, tokens);
            SessionTunnel session = new SessionTunnel(tunnel, () -> store.close(sessionId));
            store.attach(sessionId, session, context.details(tunnel, null));
            return session;
        }
        catch (GuacamoleException | RuntimeException e) {
            store.close(sessionId);
            throw e;
        }

    }

}
