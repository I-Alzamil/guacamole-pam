package io.github.ialzamil.guacamole.pam.notification;

import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleResourceNotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Hands each event PAM reports to every output, on the output's own thread,
 * so neither a rotation nor a request ever waits for a slow syslog server or
 * mail server. Each output queues up to {@link #QUEUE_SIZE} events; once
 * full, the oldest are dropped, which is logged. An event that cannot be
 * sent is tried again after {@link #RETRY_SECONDS}, so a server restarting
 * loses nothing, then dropped; while sending keeps failing, each event is
 * tried once. A failure is logged once, and again only once sending worked
 * meanwhile.
 *
 * Each server sends the events that happened on it, so with the HA module
 * every event is sent once.
 */
public final class Events {

    private static final Logger logger = LoggerFactory.getLogger(Events.class);

    static final int QUEUE_SIZE = 1000;

    private static final long SHUTDOWN_SECONDS = 2;

    /**
     * How long to wait before each new try of an event.
     */
    private static final long[] RETRY_SECONDS = { 2, 5, 10 };

    /**
     * An output, with its thread and queue.
     */
    private static final class Channel {

        final Notifier notifier;

        final ThreadPoolExecutor executor;

        final AtomicInteger dropped = new AtomicInteger();

        volatile boolean failing = false;

        Channel(Notifier notifier) {
            this.notifier = notifier;
            this.executor = new ThreadPoolExecutor(1, 1, 0, TimeUnit.MILLISECONDS,
                    new ArrayBlockingQueue<>(QUEUE_SIZE), runnable -> {
                        Thread thread = new Thread(runnable, "pam-" + notifier.getName());
                        thread.setDaemon(true);
                        return thread;
                    }, (runnable, executor) -> {
                        if (executor.isShutdown())
                            return;
                        executor.getQueue().poll();
                        if (dropped.getAndIncrement() == 0)
                            logger.warn("Events are dropped: {} cannot keep up.", notifier.getName());
                        executor.execute(runnable);
                    });
        }

        void deliver(Event event) {
            try {
                if (!notifier.isEnabled())
                    return;
                send(event);
                int lost = dropped.getAndSet(0);
                if (failing || lost > 0)
                    logger.info("Events are sent to {} again{}.", notifier.getName(),
                            lost > 0 ? " (" + lost + " dropped meanwhile)" : "");
                failing = false;
            }
            catch (Exception e) {
                if (!failing)
                    logger.error("Unable to send events to {}: {}", notifier.getName(), e.getMessage());
                else
                    logger.debug("Unable to send an event to {}: {}", notifier.getName(), e.getMessage());
                logger.debug("Unable to send an event to {}.", notifier.getName(), e);
                failing = true;
            }
        }

        /**
         * Sends an event, trying again unless sending already failed
         * before.
         */
        private void send(Event event) throws Exception {
            for (int attempt = 0; ; attempt++) {
                try {
                    notifier.send(event);
                    return;
                }
                catch (Exception e) {
                    if (failing || attempt >= RETRY_SECONDS.length)
                        throw e;
                    logger.debug("Unable to send an event to {}, trying again: {}", notifier.getName(),
                            e.getMessage());
                    try {
                        TimeUnit.SECONDS.sleep(RETRY_SECONDS[attempt]);
                    }
                    catch (InterruptedException stopped) {
                        Thread.currentThread().interrupt();
                        throw e;
                    }
                }
            }
        }

    }

    private final List<Channel> channels = new CopyOnWriteArrayList<>();

    /**
     * Adds an output, sent every event from now on.
     */
    public void add(Notifier notifier) {
        channels.add(new Channel(notifier));
    }

    /**
     * Sends a test through the output of the given name (see
     * {@link Notifier#test}).
     *
     * @throws GuacamoleResourceNotFoundException
     *     If there is no such output.
     */
    public String test(String name, String username) throws GuacamoleException {
        for (Channel channel : channels) {
            if (channel.notifier.getName().equals(name))
                return channel.notifier.test(username);
        }
        throw new GuacamoleResourceNotFoundException("No such output.");
    }

    /**
     * Reports an event to every output, without waiting.
     */
    public void publish(Event event) {
        for (Channel channel : channels) {
            try {
                channel.executor.execute(() -> channel.deliver(event));
            }
            catch (RuntimeException e) {
                // Shutting down
            }
        }
    }

    /**
     * Sends what is queued for up to {@link #SHUTDOWN_SECONDS}, then stops.
     */
    public void shutdown() {
        for (Channel channel : channels)
            channel.executor.shutdown();
        for (Channel channel : channels) {
            try {
                channel.executor.awaitTermination(SHUTDOWN_SECONDS, TimeUnit.SECONDS);
            }
            catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            channel.executor.shutdownNow();
            channel.notifier.close();
        }
    }

}
