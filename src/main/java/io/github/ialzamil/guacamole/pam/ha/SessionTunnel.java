package io.github.ialzamil.guacamole.pam.ha;

import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.net.DelegatingGuacamoleTunnel;
import org.apache.guacamole.net.GuacamoleTunnel;

/**
 * The tunnel of a recorded session, which removes it once closed: Guacamole
 * closes every tunnel when its session ends, from either side.
 */
final class SessionTunnel extends DelegatingGuacamoleTunnel {

    private final Runnable closed;

    private final AtomicBoolean isClosed = new AtomicBoolean();

    /**
     * @param closed
     *     Run once the tunnel closed, once.
     */
    SessionTunnel(GuacamoleTunnel tunnel, Runnable closed) {
        super(tunnel);
        this.closed = closed;
    }

    @Override
    public void close() throws GuacamoleException {
        try {
            super.close();
        }
        finally {
            if (isClosed.compareAndSet(false, true))
                closed.run();
        }
    }

}
