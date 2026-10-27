package io.github.ialzamil.guacamole.pam.ha;

import java.util.Collections;
import java.util.Map;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.net.GuacamoleTunnel;
import org.apache.guacamole.net.auth.Connection;
import org.apache.guacamole.net.auth.DecoratingDirectory;
import org.apache.guacamole.net.auth.DelegatingConnection;
import org.apache.guacamole.net.auth.DelegatingUserContext;
import org.apache.guacamole.net.auth.Directory;
import org.apache.guacamole.net.auth.UserContext;
import org.apache.guacamole.protocol.GuacamoleClientInformation;

/**
 * The context Guacamole's database authentication gives someone opening a
 * share link it knows, on the server the session shared runs on: their
 * session joining it is recorded, so other servers list it and can end it.
 */
final class SharingUserContext extends DelegatingUserContext {

    private final SessionStore store;

    private final SessionStore.Share share;

    private final String remoteHost;

    SharingUserContext(UserContext context, SessionStore store, SessionStore.Share share, String remoteHost) {
        super(context);
        this.store = store;
        this.share = share;
        this.remoteHost = remoteHost;
    }

    @Override
    public Directory<Connection> getConnectionDirectory() throws GuacamoleException {
        return new DecoratingDirectory<Connection>(super.getConnectionDirectory()) {

            @Override
            protected Connection decorate(Connection object) {
                return new JoiningConnection(object);
            }

            @Override
            protected Connection undecorate(Connection object) {
                return object instanceof JoiningConnection ? ((JoiningConnection) object).getUndecorated()
                        : object;
            }

        };
    }

    private final class JoiningConnection extends DelegatingConnection {

        JoiningConnection(Connection connection) {
            super(connection);
        }

        Connection getUndecorated() {
            return getDelegateConnection();
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

        @Override
        public GuacamoleTunnel connect(GuacamoleClientInformation info, Map<String, String> tokens)
                throws GuacamoleException {

            return store.joinListed(share.session, self().getIdentifier(), share.sharingProfileId, remoteHost,
                    () -> getDelegateConnection().connect(info, tokens));

        }

    }

}
