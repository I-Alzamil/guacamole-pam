package org.apache.guacamole.pam.approval;

import java.util.Collections;
import java.util.Set;

/**
 * A user deciding on requests: who they are, whether they are an
 * administrator (who may decide on any request), and the connections whose
 * requests their approval permission covers.
 */
public final class Approver {

    private final String username;
    private final boolean administrator;
    private final Set<String> connections;

    public Approver(String username, boolean administrator, Set<String> connections) {
        this.username = username;
        this.administrator = administrator;
        this.connections = Collections.unmodifiableSet(connections);
    }

    public String getUsername() {
        return username;
    }

    public boolean isAdministrator() {
        return administrator;
    }

    /**
     * Connections whose requests the approval permission covers (all of
     * them, for an administrator, whatever this contains).
     */
    public Set<String> getConnections() {
        return connections;
    }

    /**
     * Whether the user may decide on requests of at least one connection.
     */
    public boolean isApprover() {
        return administrator || !connections.isEmpty();
    }

    /**
     * Whether the user may decide on requests of the given connection.
     */
    public boolean qualifiesFor(String connectionIdentifier) {
        return administrator || connections.contains(connectionIdentifier);
    }

}
