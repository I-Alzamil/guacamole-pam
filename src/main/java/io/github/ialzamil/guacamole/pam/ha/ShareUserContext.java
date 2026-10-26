package io.github.ialzamil.guacamole.pam.ha;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleResourceNotFoundException;
import org.apache.guacamole.net.GuacamoleTunnel;
import org.apache.guacamole.net.auth.AbstractConnection;
import org.apache.guacamole.net.auth.AbstractUserContext;
import org.apache.guacamole.net.auth.AuthenticatedUser;
import org.apache.guacamole.net.auth.AuthenticationProvider;
import org.apache.guacamole.net.auth.ConnectionGroup;
import org.apache.guacamole.net.auth.ConnectionRecord;
import org.apache.guacamole.net.auth.Directory;
import org.apache.guacamole.net.auth.User;
import org.apache.guacamole.net.auth.simple.SimpleConnectionGroup;
import org.apache.guacamole.net.auth.simple.SimpleDirectory;
import org.apache.guacamole.net.auth.simple.SimpleUser;
import org.apache.guacamole.protocol.GuacamoleClientInformation;
import org.apache.guacamole.protocol.GuacamoleConfiguration;

/**
 * What someone opening a share link sees, as Guacamole shows it: the one
 * connection shared, which joins the session shared, on whichever server it
 * runs.
 */
final class ShareUserContext extends AbstractUserContext {

    private final AuthenticationProvider authenticationProvider;

    private final SharedConnection connection;

    ShareUserContext(AuthenticationProvider authenticationProvider, SessionStore store,
            SessionStore.Share share, AuthenticatedUser user) {
        this.authenticationProvider = authenticationProvider;
        this.connection = new SharedConnection(store, share, user);
    }

    @Override
    public User self() {
        return new SimpleUser(AuthenticatedUser.ANONYMOUS_IDENTIFIER);
    }

    @Override
    public AuthenticationProvider getAuthenticationProvider() {
        return authenticationProvider;
    }

    @Override
    public Directory<org.apache.guacamole.net.auth.Connection> getConnectionDirectory() {
        return new SimpleDirectory<org.apache.guacamole.net.auth.Connection>(connection);
    }

    @Override
    public ConnectionGroup getRootConnectionGroup() {
        return new SimpleConnectionGroup(DEFAULT_ROOT_CONNECTION_GROUP, DEFAULT_ROOT_CONNECTION_GROUP,
                Collections.singleton(connection.getIdentifier()), Collections.<String>emptySet());
    }

    /**
     * The connection of a share link, named as the connection shared.
     */
    private static final class SharedConnection extends AbstractConnection {

        private final SessionStore store;

        private final String keyHash;

        private final AuthenticatedUser user;

        SharedConnection(SessionStore store, SessionStore.Share share, AuthenticatedUser user) {
            this.store = store;
            this.keyHash = share.keyHash;
            this.user = user;
            setIdentifier(keyHash.substring(0, 32));
            setParentIdentifier(DEFAULT_ROOT_CONNECTION_GROUP);
            setName(share.session.connectionId);
            GuacamoleConfiguration configuration = new GuacamoleConfiguration();
            try (Connection db = store.getDatabase().connect();
                 PreparedStatement statement = db.prepareStatement("SELECT connection_name, protocol FROM"
                     + " guacamole_connection WHERE connection_id = ?")) {
                Integer id = Sql.id(share.session.connectionId);
                statement.setInt(1, id != null ? id : -1);
                try (ResultSet results = statement.executeQuery()) {
                    if (results.next()) {
                        setName(results.getString(1));
                        configuration.setProtocol(results.getString(2));
                    }
                }
            }
            catch (SQLException e) {
                // The name stays the connection's identifier
            }
            setConfiguration(configuration);
        }

        @Override
        public int getActiveConnections() {
            return 0;
        }

        @Override
        public Map<String, String> getAttributes() {
            return Collections.<String, String>emptyMap();
        }

        @Override
        public void setAttributes(Map<String, String> attributes) {
        }

        @Override
        public Date getLastActive() {
            return null;
        }

        @Override
        @Deprecated
        public List<? extends ConnectionRecord> getHistory() {
            return Collections.<ConnectionRecord>emptyList();
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
         * Joins the session shared, if still open.
         */
        @Override
        public GuacamoleTunnel connect(GuacamoleClientInformation info, Map<String, String> tokens)
                throws GuacamoleException {
            SessionStore.Share share = store.findShare(keyHash);
            if (share == null)
                throw new GuacamoleResourceNotFoundException("No existing connection to be joined.");
            return Joins.open(store, share.session, share.sharingProfileId, user.getIdentifier(),
                    user.getCredentials().getRemoteAddress(), info, tokens);
        }

    }

}
