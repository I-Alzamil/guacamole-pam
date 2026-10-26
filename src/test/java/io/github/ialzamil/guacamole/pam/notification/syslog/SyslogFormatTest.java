package io.github.ialzamil.guacamole.pam.notification.syslog;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.nio.charset.StandardCharsets;

import org.junit.Test;

import io.github.ialzamil.guacamole.pam.notification.Event;
import io.github.ialzamil.guacamole.pam.notification.EventType;

public class SyslogFormatTest {

    private static String format(Event event) {
        return new String(SyslogFormat.format(event, 10, null), StandardCharsets.UTF_8);
    }

    @Test
    public void writesTheHeaderThenTheFields() {
        String message = format(Event.of(EventType.CHECKOUT_STARTED).user("bob").connection("3", "web01")
                .checkout(12).reason("Ticket \"42\"\nurgent"));
        // authpriv (10) * 8 + notice (5)
        assertTrue(message, message.startsWith("<85>1 "));
        assertTrue(message, message.matches("<85>1 \\S+Z \\S+ guacamole-pam - checkout-started - User \"bob\""
                + " checked out \"web01\"\\. event=\"checkout-started\" user=\"bob\" connection=\"web01\""
                + " connection-id=\"3\" checkout=\"12\" reason=\"Ticket \\\\\"42\\\\\" urgent\""));
    }

    @Test
    public void namesTheFacilityAndSeverity() {
        assertEquals(16, SyslogSettings.facility("local0"));
        assertEquals(23, SyslogSettings.facility("local7"));
        assertEquals(4, SyslogSettings.facility("auth"));
        assertTrue(new String(SyslogFormat.format(Event.of(EventType.ROTATION_FAILED), 16, "pam"),
                StandardCharsets.UTF_8).startsWith("<131>1 "));
    }

    @Test
    public void cutsLongMessagesBetweenCharacters() {
        StringBuilder detail = new StringBuilder();
        for (int i = 0; i < 5000; i++)
            detail.append('é');
        byte[] message = SyslogFormat.format(Event.of(EventType.ROTATION_FAILED).detail(detail.toString()), 10, null);
        assertTrue(message.length <= SyslogFormat.MAX_BYTES);
        assertTrue(new String(message, StandardCharsets.UTF_8).endsWith("é"));
    }

    @Test
    public void refusesAppNamesWithSpaces() {
        SyslogFormat.checkAppName("guac-pam");
        try {
            SyslogFormat.checkAppName("guac pam");
            fail("accepted");
        }
        catch (IllegalArgumentException e) {
            // Expected
        }
    }

}
