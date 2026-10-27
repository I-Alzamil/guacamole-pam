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
                EmailText.standard(EmailTemplates.Kind.APPROVAL, null).subject(SUBMITTED, Audience.Role.APPROVER));
    }

    @Test
    public void approversAreSentToTheApprovalsTab() {
        String body = EmailText.standard(EmailTemplates.Kind.APPROVAL, "https://guac.example.org/guacamole")
                .body(SUBMITTED, Audience.Role.APPROVER);
        assertTrue(body, body.contains("Connection: web Bcc: x@evil\nUser: bob\nRequest: 12\nReason: Ticket 42\n"));
        assertTrue(body, body.contains("Approve or deny it on the Approvals tab:"
                + " https://guac.example.org/guacamole/#/settings/pam-approvals\n"));
        assertTrue(body, body.contains("You receive this as an approver of the connection."));
    }

    @Test
    public void withoutAnAddressThereIsNoLink() {
        String body = EmailText.standard(EmailTemplates.Kind.ENDED, null).body(Event.of(EventType.CHECKOUT_EXPIRED).user("bob")
                .connection("7", "web"), Audience.Role.OWN);
        assertTrue(body, body.contains("\nTo use it again, request it again in Guacamole\n"));
        assertTrue(body, !body.contains("http"));
        assertTrue(body, body.contains("about your own requests and access"));
    }

    private static EmailLanguage language(String subject, String body) {
        EmailLanguage language = new EmailLanguage();
        language.setCode("xx");
        language.setName("Test");
        language.getTemplates().put("decision", new EmailLanguage.Template(subject, body));
        return language;
    }

    @Test
    public void templatesReplaceTheirPlaceholdersByValuesAsText() {
        EmailLanguage test = language("{{PAM}} {event} for {user}", "Hi {user},\n\n{reason}\n{link}\n\n\nBye {{x}}")
                .over(EmailLanguages.getBuiltIn());
        EmailText text = new EmailText(test, EmailTemplates.Kind.DECISION, null, java.time.ZoneId.of("Asia/Riyadh"));
        Event event = Event.of(EventType.REQUEST_DENIED).user("{actor}").actor("ann").reason("Not\ntoday")
                .period(0L, null);
        assertEquals("{PAM} request-denied for {actor}", text.subject(event, Audience.Role.OWN));
        // No link without Guacamole's address: its line, and the blank
        // ones around it, make one blank line
        assertEquals("Hi {actor},\n\nNot today\n\nBye {x}\n", text.body(event, Audience.Role.OWN));
        assertTrue(new EmailText(language("x", "{starts}").over(EmailLanguages.getBuiltIn()),
                EmailTemplates.Kind.DECISION, null, java.time.ZoneId.of("Asia/Riyadh")).body(event,
                Audience.Role.OWN).startsWith("1970-01-01 03:00:00 +03:00 (Asia/Riyadh)"));
    }

    /**
     * A language's own messages, and English for those it leaves out.
     */
    @Test
    public void writesInTheLanguageGiven() throws Exception {
        EmailLanguage french = new EmailLanguage();
        french.setCode("fr");
        french.setName("Français");
        french.getMessages().put("SUMMARY_REQUEST_DENIED", "\"{actor}\" a refusé la demande de \"{user}\".");
        french.getMessages().put("LABEL_REASON", "Motif");
        EmailText text = new EmailText(EmailLanguages.validate(french).over(EmailLanguages.getBuiltIn()),
                EmailTemplates.Kind.DECISION, null, java.time.ZoneOffset.UTC);
        Event event = Event.of(EventType.REQUEST_DENIED).user("bob").actor("ann").connection("7", "web")
                .reason("Pas aujourd'hui");
        assertEquals("[Guacamole PAM] \"ann\" a refusé la demande de \"bob\".", text.subject(event, Audience.Role.OWN));
        String body = text.body(event, Audience.Role.OWN);
        assertTrue(body, body.contains("\nMotif: Pas aujourd'hui\n"));
        assertTrue(body, body.contains("\nConnection: web\n"));
        assertTrue(body, body.contains("You receive this about your own requests and access."));
    }

    @Test
    public void refusesWhatIsNotALanguage() {
        refused("not a language code", lang("english", "English"));
        refused("The name must be one line", lang("fr", ""));
        EmailLanguage message = lang("fr", "Français");
        message.getMessages().put("SUMMARY_NOPE", "x");
        refused("There is no message \"SUMMARY_NOPE\".", message);
        EmailLanguage placeholder = lang("fr", "Français");
        placeholder.getMessages().put("LABEL_USER", "{usr}");
        refused("Message \"LABEL_USER\" has an unknown placeholder {usr}.", placeholder);
        EmailLanguage kind = lang("fr", "Français");
        kind.getTemplates().put("weekly", new EmailLanguage.Template("x", "y"));
        refused("There is no kind of email \"weekly\".", kind);
        EmailLanguage format = lang("fr", "Français");
        format.setFormat("platforms");
        refused("This is not a file of an email language", format);
    }

    private static EmailLanguage lang(String code, String name) {
        EmailLanguage language = new EmailLanguage();
        language.setCode(code);
        language.setName(name);
        return language;
    }

    private static void refused(String start, EmailLanguage language) {
        try {
            EmailLanguages.validate(language);
            fail("accepted");
        }
        catch (org.apache.guacamole.GuacamoleClientException e) {
            assertTrue(e.getMessage(), e.getMessage().contains(start));
        }
    }

    @Test
    public void eachKindHasItsTemplate() {
        assertEquals(EmailTemplates.Kind.APPROVAL, EmailTemplates.Kind.of(EventType.REQUEST_SUBMITTED));
        assertEquals(EmailTemplates.Kind.DECISION, EmailTemplates.Kind.of(EventType.REQUEST_DENIED));
        assertEquals(EmailTemplates.Kind.DECISION, EmailTemplates.Kind.of(EventType.REQUEST_EXPIRED));
        assertEquals(EmailTemplates.Kind.ENDED, EmailTemplates.Kind.of(EventType.CHECKOUT_EXPIRED));
        assertEquals(EmailTemplates.Kind.OTHER, EmailTemplates.Kind.of(EventType.SESSION_STARTED));
    }

    /**
     * English, built in, has a message for every key PAM uses, a template
     * for every kind, and only placeholders that exist; and is valid as an
     * imported language would be.
     */
    @Test
    public void englishIsComplete() throws Exception {
        EmailLanguage english = EmailLanguages.getBuiltIn();
        for (EmailTemplates.Kind kind : EmailTemplates.Kind.values())
            assertTrue(kind.getName(), english.template(kind) != null && english.template(kind).getBody() != null);
        for (EventType type : EventType.values())
            assertTrue(type.name(), english.getMessages().containsKey("SUMMARY_" + type.name()));
        EmailLanguages.validate(english);
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
