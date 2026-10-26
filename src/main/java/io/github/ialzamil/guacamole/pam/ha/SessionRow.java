package io.github.ialzamil.guacamole.pam.ha;

import java.util.Date;

/**
 * A session of any server, as recorded in pam_ha_session.
 */
final class SessionRow {

    /**
     * The guacd a session runs on, and its connection there, which other
     * sessions join.
     */
    static final class Guacd {

        final String hostname;
        final int port;
        final boolean ssl;
        final String connectionId;

        Guacd(String hostname, int port, boolean ssl, String connectionId) {
            this.hostname = hostname;
            this.port = port;
            this.ssl = ssl;
            this.connectionId = connectionId;
        }

    }

    final String sessionId;
    final String serverId;

    /**
     * The identifier of its tunnel, which is also that of the active
     * connection Guacamole lists for it; null until it opened.
     */
    final String tunnelId;

    /**
     * The connection it runs: the one picked when it went through a
     * balancing group, which is then set too.
     */
    final String connectionId;
    final String connectionGroupId;

    /**
     * The sharing profile a session joining another joined with, if any.
     */
    final String sharingProfileId;

    /**
     * Whether it joins another session, rather than being one of its own:
     * joining sessions are not counted, as in Guacamole.
     */
    final boolean joined;

    final String username;
    final String remoteHost;
    final Date started;

    /**
     * Where it runs, null if other servers cannot join it.
     */
    final Guacd guacd;

    SessionRow(String sessionId, String serverId, String tunnelId, String connectionId, String connectionGroupId,
            String sharingProfileId, boolean joined, String username, String remoteHost, Date started,
            Guacd guacd) {
        this.sessionId = sessionId;
        this.serverId = serverId;
        this.tunnelId = tunnelId;
        this.connectionId = connectionId;
        this.connectionGroupId = connectionGroupId;
        this.sharingProfileId = sharingProfileId;
        this.joined = joined;
        this.username = username;
        this.remoteHost = remoteHost;
        this.started = started;
        this.guacd = guacd;
    }

    /**
     * Whether other sessions can join it.
     */
    boolean joinable() {
        return tunnelId != null && connectionId != null && guacd != null && guacd.connectionId != null;
    }

}
