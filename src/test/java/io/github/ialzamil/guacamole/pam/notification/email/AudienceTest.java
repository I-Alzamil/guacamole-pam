package io.github.ialzamil.guacamole.pam.notification.email;

import static org.junit.Assert.assertEquals;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.junit.Test;

import io.github.ialzamil.guacamole.pam.notification.Event;
import io.github.ialzamil.guacamole.pam.notification.EventType;

/**
 * Who is emailed each event, and as what: administrators "admin" and
 * "root", approvers of connection 7 "ann" and "abe", and "root" approving
 * too.
 */
public class AudienceTest {

    private final Map<String, Map<Audience.Role, Boolean>> preferences = new HashMap<>();

    private final Audience.Source source = new Audience.Source() {

        @Override
        public Set<String> getAdministrators() {
            return new HashSet<>(Arrays.asList("admin", "root"));
        }

        @Override
        public Set<String> getApproversOf(String connectionIdentifier) {
            return "7".equals(connectionIdentifier) ? new HashSet<>(Arrays.asList("ann", "abe", "root"))
                    : new HashSet<>();
        }

        @Override
        public Map<String, Map<Audience.Role, Boolean>> getPreferences(Collection<String> usernames) {
            return preferences;
        }

    };

    private String audience(Event event) throws Exception {
        Map<String, Audience.Role> audience = Audience.of(event, source);
        StringBuilder text = new StringBuilder();
        for (String user : new java.util.TreeSet<>(audience.keySet()))
            text.append(text.length() == 0 ? "" : " ").append(user).append('=').append(audience.get(user).getName());
        return text.toString();
    }

    @Test
    public void aRequestGoesToItsApproversButTheRequester() throws Exception {
        assertEquals("abe=approvals admin=everything ann=approvals root=approvals",
                audience(Event.of(EventType.REQUEST_SUBMITTED).user("bob").connection("7", "web")));
        assertEquals("abe=approvals admin=everything root=approvals",
                audience(Event.of(EventType.REQUEST_SUBMITTED).user("ann").connection("7", "web")));
    }

    @Test
    public void aDecisionGoesToTheRequesterAndTheOtherApprovers() throws Exception {
        assertEquals("abe=approvals admin=everything bob=own root=approvals",
                audience(Event.of(EventType.REQUEST_GRANTED).user("bob").actor("ann").connection("7", "web")));
        assertEquals("abe=approvals admin=everything bob=own root=approvals",
                audience(Event.of(EventType.REQUEST_DENIED).user("bob").actor("ann").connection("7", "web")));
        // A partial approval: not yet the requester's concern
        assertEquals("abe=approvals admin=everything root=approvals",
                audience(Event.of(EventType.REQUEST_APPROVED).user("bob").actor("ann").connection("7", "web")));
    }

    @Test
    public void accessEndingGoesToItsHolderUnlessTheyEndedIt() throws Exception {
        assertEquals("admin=everything bob=own root=everything",
                audience(Event.of(EventType.CHECKOUT_EXPIRED).user("bob").connection("7", "web")));
        assertEquals("bob=own root=everything",
                audience(Event.of(EventType.CHECKOUT_REVOKED).user("bob").actor("admin").connection("7", "web")));
        assertEquals("admin=everything root=everything",
                audience(Event.of(EventType.CHECKOUT_RELEASED).user("bob").actor("bob").connection("7", "web")));
        assertEquals("root=everything",
                audience(Event.of(EventType.CHECKOUT_RELEASED).user("admin").actor("admin").connection("7", "web")));
    }

    @Test
    public void everythingElseGoesToAdministratorsOnly() throws Exception {
        assertEquals("admin=everything root=everything",
                audience(Event.of(EventType.ROTATION_FAILED).connection("7", "web")));
        assertEquals("root=everything", audience(Event.of(EventType.SETTINGS_CHANGED).actor("admin")));
        assertEquals("admin=everything root=everything",
                audience(Event.of(EventType.SESSION_STARTED).user("bob").connection("7", "web")));
        assertEquals("", audience(Event.of(EventType.TEST).actor("admin")));
    }

    @Test
    public void eachUserChoosesWhatTheyReceive() throws Exception {
        Map<Audience.Role, Boolean> noApprovals = new HashMap<>();
        noApprovals.put(Audience.Role.APPROVER, false);
        preferences.put("root", noApprovals);
        Map<Audience.Role, Boolean> nothing = new HashMap<>();
        for (Audience.Role role : Audience.Role.values())
            nothing.put(role, false);
        preferences.put("abe", nothing);
        // root still receives it as an administrator
        assertEquals("admin=everything ann=approvals root=everything",
                audience(Event.of(EventType.REQUEST_SUBMITTED).user("bob").connection("7", "web")));
    }

}
