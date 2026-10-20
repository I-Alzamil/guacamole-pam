package org.apache.guacamole.pam.rotation;

import org.apache.guacamole.GuacamoleException;

/**
 * Whether the user of an open session may still use its connection, checked
 * again while the session lasts, so it closes once their access is revoked.
 */
@FunctionalInterface
public interface SessionAccess {

    /**
     * @throws GuacamoleException
     *     If it cannot be told now, such as while the database is
     *     unreachable: the session then stays open.
     */
    boolean isAllowed() throws GuacamoleException;

}
