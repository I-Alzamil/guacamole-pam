package org.apache.guacamole.pam;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.guacamole.GuacamoleClientException;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.form.Field;
import org.apache.guacamole.form.Form;
import org.apache.guacamole.net.DelegatingGuacamoleTunnel;
import org.apache.guacamole.net.GuacamoleTunnel;
import org.apache.guacamole.net.auth.Connection;
import org.apache.guacamole.net.auth.DelegatingConnection;
import org.apache.guacamole.pam.checkout.CheckoutService;
import org.apache.guacamole.pam.rotation.RotationService;
import org.apache.guacamole.protocol.GuacamoleClientInformation;

/**
 * Connection which refuses sessions without the checkout its access
 * requires, reports when its tunnels open and close (so the rotation service
 * knows when it is in use, and can close them when a checkout ends), and
 * always exposes its password management attributes to the editor.
 */
public class PamConnection extends DelegatingConnection {

    /**
     * Names of all attributes of the password management forms.
     */
    private static final List<String> ATTRIBUTE_NAMES = new ArrayList<>();

    static {
        for (Form form : PamAttributes.CONNECTION_FORMS) {
            for (Field field : form.getFields())
                ATTRIBUTE_NAMES.add(field.getName());
        }
    }

    private final RotationService rotationService;

    private final CheckoutService checkoutService;

    /**
     * The user this connection is presented to, and whether they are an
     * administrator (who bypasses access requests).
     */
    private final String username;
    private final boolean administrator;

    public PamConnection(Connection connection, RotationService rotationService,
            CheckoutService checkoutService, String username, boolean administrator) {
        super(connection);
        this.rotationService = rotationService;
        this.checkoutService = checkoutService;
        this.username = username;
        this.administrator = administrator;
    }

    public Connection getUndecorated() {
        return getDelegateConnection();
    }

    /**
     * For Accounts, which have no sessions, the number of users holding the
     * password, so Guacamole shows "Currently in use by N users" for them
     * like for connections in use.
     */
    @Override
    public int getActiveConnections() {
        Integer holders = checkoutService.getAccountHolders(getIdentifier());
        return holders != null ? holders : super.getActiveConnections();
    }

    /**
     * Includes every password management attribute, null when unset. When
     * editing an existing connection, the web UI only shows attributes
     * present here, and the database returns only attributes with a value.
     */
    @Override
    public Map<String, String> getAttributes() {

        Map<String, String> attributes = new HashMap<>(super.getAttributes());
        for (String name : ATTRIBUTE_NAMES) {
            String value = attributes.get(name);
            if (value == null || value.isEmpty())
                attributes.put(name, null);
        }

        return attributes;

    }

    /**
     * Stores empty password management attributes as unset, rather than as
     * empty values.
     */
    @Override
    public void setAttributes(Map<String, String> attributes) {

        Map<String, String> cleaned = new HashMap<>(attributes);
        for (String name : ATTRIBUTE_NAMES) {
            String value = cleaned.get(name);
            if (value != null && value.trim().isEmpty())
                cleaned.put(name, null);
        }

        super.setAttributes(cleaned);

    }

    /**
     * Opens every session of the connection, checking access and tracking
     * the session. The wrapped connection is called directly: going through
     * DelegatingConnection would route through the deprecated
     * connect(info), which calls back here.
     */
    @Override
    public GuacamoleTunnel connect(GuacamoleClientInformation info, Map<String, String> tokens)
            throws GuacamoleException {

        // Password request connections never open a session, even if the
        // web UI is bypassed; their password is requested instead
        if (AccountProtocol.NAME.equals(getConfiguration().getProtocol()))
            throw new GuacamoleClientException("This is a password request connection."
                    + " Select it on the home screen to request its password.");

        // Connections requiring a request need an active checkout
        final String identifier = getIdentifier();
        checkoutService.requireAccess(identifier, username, administrator);

        GuacamoleTunnel tunnel = getDelegateConnection().connect(info, tokens);

        GuacamoleTunnel tracked = new DelegatingGuacamoleTunnel(tunnel) {

            private final AtomicBoolean closed = new AtomicBoolean();

            @Override
            public void close() throws GuacamoleException {
                try {
                    super.close();
                }
                finally {
                    if (closed.compareAndSet(false, true))
                        rotationService.sessionEnded(identifier, this);
                }
            }

        };

        rotationService.sessionStarted(identifier, username, tracked);
        return tracked;

    }

    /**
     * The deprecated variant without tokens, which DelegatingConnection
     * would send straight to the wrapped connection: routed through the
     * checks above instead, as the Connection API itself does. Delete this
     * if a future Guacamole release removes the method.
     */
    @Override
    @Deprecated
    public GuacamoleTunnel connect(GuacamoleClientInformation info) throws GuacamoleException {
        return connect(info, Collections.<String, String>emptyMap());
    }

}
