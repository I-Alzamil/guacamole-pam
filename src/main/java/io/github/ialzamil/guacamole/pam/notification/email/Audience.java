package io.github.ialzamil.guacamole.pam.notification.email;

import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import org.apache.guacamole.GuacamoleException;

import io.github.ialzamil.guacamole.pam.notification.Event;

/**
 * Who is emailed an event, and as what:
 *
 * <ul>
 * <li>the user it concerns ({@link Role#OWN}): when their request is
 * granted, denied or rejected, and when their checkout expires or is ended by
 * someone else;</li>
 * <li>the approvers of its connection ({@link Role#APPROVER}): a request
 * awaiting their approval, and another approver's decision on one;</li>
 * <li>administrators ({@link Role#ADMINISTRATOR}): every event.</li>
 * </ul>
 *
 * Nobody is emailed what they did themselves, nor their own request as an
 * approver. Each user is emailed once per event, as the first of their roles
 * whose emails they want (see {@link EmailPreferences}).
 */
final class Audience {

    /**
     * Why a user is emailed, in order of precedence.
     */
    enum Role {

        OWN("own"),
        APPROVER("approvals"),
        ADMINISTRATOR("everything");

        private final String name;

        Role(String name) {
            this.name = name;
        }

        /**
         * Its name in preferences: "own", "approvals" or "everything".
         */
        String getName() {
            return name;
        }

        static Role named(String name) {
            for (Role role : values()) {
                if (role.name.equals(name))
                    return role;
            }
            return null;
        }

    }

    /**
     * Where the users to email come from.
     */
    interface Source {

        Set<String> getAdministrators() throws GuacamoleException;

        Set<String> getApproversOf(String connectionIdentifier) throws GuacamoleException;

        /**
         * What each of the given users wants, by username; those missing
         * want every kind.
         */
        Map<String, Map<Role, Boolean>> getPreferences(Collection<String> usernames) throws GuacamoleException;

    }

    private Audience() {
    }

    /**
     * The users to email the event, each with their role, in order of
     * precedence.
     */
    static Map<String, Role> of(Event event, Source source) throws GuacamoleException {

        Map<Role, Set<String>> candidates = new LinkedHashMap<>();
        for (Role role : Role.values())
            candidates.put(role, new HashSet<>());

        String user = event.getUser();
        String actor = event.getActor();
        boolean byAnother = actor != null && !actor.equals(user);
        boolean notByThem = user != null && !user.equals(actor);

        switch (event.getType()) {

            case REQUEST_SUBMITTED:
            case REQUEST_APPROVED:
                approvers(event, source, candidates);
                break;

            case REQUEST_GRANTED:
            case REQUEST_DENIED:
                if (notByThem)
                    candidates.get(Role.OWN).add(user);
                approvers(event, source, candidates);
                break;

            case CHECKOUT_EXPIRED:
                candidates.get(Role.OWN).add(user);
                break;

            case CHECKOUT_REVOKED:
                if (byAnother)
                    candidates.get(Role.OWN).add(user);
                break;

            case TEST:
                return new LinkedHashMap<>();

            default:
                break;

        }
        candidates.get(Role.ADMINISTRATOR).addAll(source.getAdministrators());

        // Never what they did themselves, and what concerns them only as
        // its user, chosen above
        for (Role role : new Role[] { Role.APPROVER, Role.ADMINISTRATOR }) {
            candidates.get(role).remove(user);
            candidates.get(role).remove(actor);
        }

        Set<String> everyone = new HashSet<>();
        for (Set<String> users : candidates.values())
            everyone.addAll(users);
        Map<String, Map<Role, Boolean>> preferences = source.getPreferences(everyone);

        Map<String, Role> audience = new LinkedHashMap<>();
        for (Map.Entry<Role, Set<String>> entry : candidates.entrySet()) {
            for (String username : entry.getValue()) {
                Map<Role, Boolean> wanted = preferences.get(username);
                if (!audience.containsKey(username) && (wanted == null || !Boolean.FALSE.equals(wanted.get(entry.getKey()))))
                    audience.put(username, entry.getKey());
            }
        }
        return audience;

    }

    /**
     * The approvers of the event's connection, but the one who decided.
     */
    private static void approvers(Event event, Source source, Map<Role, Set<String>> candidates)
            throws GuacamoleException {
        if (event.getConnectionIdentifier() != null)
            candidates.get(Role.APPROVER).addAll(source.getApproversOf(event.getConnectionIdentifier()));
    }

}
