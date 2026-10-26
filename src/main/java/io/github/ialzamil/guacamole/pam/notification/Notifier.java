package io.github.ialzamil.guacamole.pam.notification;

import org.apache.guacamole.GuacamoleException;

/**
 * An output of events, such as syslog or email, configured on the settings
 * page. Sent events on its own thread (see {@link Events}), one at a time,
 * so it may block while sending; only tests come from other threads.
 */
public interface Notifier {

    /**
     * Its name in logs: "syslog".
     */
    String getName();

    /**
     * Whether it is turned on, read again for each event, so a change on the
     * settings page applies from the next one.
     */
    boolean isEnabled() throws Exception;

    /**
     * Sends an event.
     *
     * @throws Exception
     *     If it could not be sent: logged, and the event dropped.
     */
    void send(Event event) throws Exception;

    /**
     * Sends a test now, as configured, for the settings page, on behalf of
     * the given administrator: on the caller's thread, apart from the
     * events.
     *
     * @return
     *     What was sent, and where.
     *
     * @throws GuacamoleException
     *     If it is not configured, or the test could not be sent, saying
     *     why.
     */
    String test(String username) throws GuacamoleException;

    /**
     * Releases what it keeps open, such as a connection.
     */
    void close();

}
