package io.github.ialzamil.guacamole.pam.ha;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.net.event.listener.Listener;

/**
 * Counts failed logins on every server, for the ban extension's limits (see
 * {@link BanSync}), when the HA module runs.
 */
public class HaListener implements Listener {

    @Override
    public void handleEvent(Object event) throws GuacamoleException {
        if (!Settings.isEnabled())
            return;
        BanSync bans = Cluster.get().getBans();
        if (bans != null)
            bans.handleEvent(event);
    }

}
