package io.github.ialzamil.guacamole.pam.ha;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;

import com.sun.net.httpserver.HttpServer;

import org.apache.guacamole.GuacamoleException;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

/**
 * Who a server says it is, to those giving the secret, and what checking
 * the URL of a server finds.
 */
public class StatusTest {

    private static final String SERVER_ID = "374dd2c2-9738-4039-a2df-7f4667e19900";

    @Rule
    public TemporaryFolder folder = new TemporaryFolder();

    private HttpServer server;

    private String url;

    @Before
    public void setUp() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/guacamole/api/ext/pam-ha/ping", exchange -> {
            String secret = exchange.getRequestHeaders().getFirst(Recordings.SECRET_HEADER);
            byte[] body = SERVER_ID.getBytes(StandardCharsets.UTF_8);
            if (!"s3cret".equals(secret)) {
                exchange.sendResponseHeaders(403, -1);
                exchange.close();
                return;
            }
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream output = exchange.getResponseBody()) {
                output.write(body);
            }
        });
        server.createContext("/moved/api/ext/pam-ha/ping", exchange -> {
            redirectedSecret = exchange.getRequestHeaders().getFirst(Recordings.SECRET_HEADER);
            exchange.getResponseHeaders().add("Location", url + "api/ext/pam-ha/ping");
            exchange.sendResponseHeaders(302, -1);
            exchange.close();
        });
        server.createContext("/guacamole/", exchange -> {
            followedSecret = exchange.getRequestHeaders().getFirst(Recordings.SECRET_HEADER);
            exchange.sendResponseHeaders(404, -1);
            exchange.close();
        });
        server.start();
        url = "http://127.0.0.1:" + server.getAddress().getPort() + "/guacamole/";
    }

    /**
     * The secret as a redirecting URL got it, and as where it leads got it,
     * if it was followed.
     */
    private volatile String redirectedSecret;

    private volatile String followedSecret;

    @After
    public void tearDown() {
        server.stop(0);
    }

    private Config config(String... properties) throws GuacamoleException {
        return new Config(new TestEnvironment(properties).home(folder.getRoot()));
    }

    @Test
    public void checksTheSecret() throws GuacamoleException {
        Config config = config("pam-ha-secret", "s3cret");
        assertTrue(config.isSecret("s3cret"));
        for (String secret : new String[] { null, "", "s3cre", "s3cret " })
            assertFalse(secret, config.isSecret(secret));
        assertFalse(config().isSecret(null));
        assertFalse(config().isSecret(""));
    }

    @Test
    public void findsWhoAUrlReaches() throws GuacamoleException {
        Config config = config("pam-ha-secret", "s3cret");
        assertEquals(Status.Reach.OK, Status.reach(SERVER_ID, url, config));
        assertEquals(Status.Reach.OK, Status.reach(SERVER_ID, url.replaceAll("/$", ""), config));
        assertEquals(Status.Reach.OTHER_SERVER, Status.reach("another", url, config));
        assertEquals(Status.Reach.WRONG_SECRET, Status.reach(SERVER_ID, url, config("pam-ha-secret", "other")));
        assertEquals(Status.Reach.UNREACHABLE, Status.reach(SERVER_ID, url + "missing/", config));
        assertEquals(Status.Reach.UNREACHABLE, Status.reach(SERVER_ID, "not a url", config));
        assertEquals(Status.Reach.NO_URL, Status.reach(SERVER_ID, null, config));
        assertEquals(Status.Reach.NO_SECRET, Status.reach(SERVER_ID, url, config()));
    }

    @Test
    public void neverFollowsRedirects() throws GuacamoleException {
        String moved = url.replace("/guacamole/", "/moved/");
        assertEquals(Status.Reach.UNREACHABLE, Status.reach(SERVER_ID, moved, config("pam-ha-secret", "s3cret")));
        assertEquals("s3cret", redirectedSecret);
        assertNull("the secret followed the redirect", followedSecret);
    }

}
