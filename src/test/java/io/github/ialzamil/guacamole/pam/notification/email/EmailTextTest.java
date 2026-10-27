package io.github.ialzamil.guacamole.pam.notification.email;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;

import io.github.ialzamil.guacamole.pam.notification.Event;
import io.github.ialzamil.guacamole.pam.notification.EventType;

public class EmailTextTest {

    private static final Event SUBMITTED = Event.of(EventType.REQUEST_SUBMITTED).user("bob")
            .connection("7", "web\r\nBcc: x@evil").request(12).reason("Ticket 42");

    @Test
    public void subjectsAreOneLine() {
        assertEquals("[Guacamole PAM] User \"bob\" requested \"web Bcc: x@evil\", which awaits approval.",
                EmailText.subject(SUBMITTED));
    }

    @Test
    public void approversAreSentToTheApprovalsTab() {
        String body = EmailText.body(SUBMITTED, Audience.Role.APPROVER, "https://guac.example.org/guacamole");
        assertTrue(body, body.contains("Connection: web Bcc: x@evil\nUser: bob\nRequest: 12\nReason: Ticket 42\n"));
        assertTrue(body, body.contains("Approve or deny it on the Approvals tab:"
                + " https://guac.example.org/guacamole/#/settings/pam-approvals\n"));
        assertTrue(body, body.contains("You receive this as an approver of the connection."));
    }

    @Test
    public void withoutAnAddressThereIsNoLink() {
        String body = EmailText.body(Event.of(EventType.CHECKOUT_EXPIRED).user("bob").connection("7", "web"),
                Audience.Role.OWN, null);
        assertTrue(body, body.contains("\nTo use it again, request it again in Guacamole\n"));
        assertTrue(body, !body.contains("http"));
        assertTrue(body, body.contains("about your own requests and access"));
    }

    @Test
    public void checksAddresses() {
        EmailSettings.checkAddress("pam@example.org");
        EmailSettings.checkAddress("Guacamole PAM <pam@example.org>");
        for (String bad : new String[] { "pam", "a@b.org, c@d.org", "pam@" }) {
            try {
                EmailSettings.checkAddress(bad);
                fail("accepted " + bad);
            }
            catch (IllegalArgumentException e) {
                // Expected
            }
        }
    }

}
