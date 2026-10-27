package io.github.ialzamil.guacamole.pam.notification.email;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import org.apache.guacamole.GuacamoleClientException;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleServerException;

import io.github.ialzamil.guacamole.pam.db.PamDatabase;
import io.github.ialzamil.guacamole.pam.db.SqlDialect;

/**
 * Which emails each user wants, stored in "pam_user_preference" beside
 * their badges: "everything" (all PAM events, for administrators),
 * "approvals" (requests awaiting their approval, and other approvers'
 * decisions on them) and "own" (decisions on their requests, and their
 * access ending). Each is sent unless turned off.
 */
public class EmailPreferences {

    /**
     * Column of each kind, by name, in the order the Preferences tab lists
     * them.
     */
    static final Map<Audience.Role, String> COLUMNS = new LinkedHashMap<>();

    static {
        COLUMNS.put(Audience.Role.ADMINISTRATOR, "admin_email");
        COLUMNS.put(Audience.Role.APPROVER, "approval_email");
        COLUMNS.put(Audience.Role.OWN, "own_email");
    }

    private final PamDatabase database;

    public EmailPreferences(PamDatabase database) {
        this.database = database;
    }

    /**
     * Whether the user wants each kind, by name.
     */
    public Map<String, Boolean> get(String username) throws GuacamoleException {
        Map<String, Boolean> wanted = new LinkedHashMap<>();
        Map<Audience.Role, Boolean> roles = get(Collections.singleton(username)).get(username);
        for (Audience.Role role : COLUMNS.keySet())
            wanted.put(role.getName(), roles == null || roles.get(role));
        return wanted;
    }

    /**
     * What each of the given users wants, by username; users who never
     * chose are missing, wanting every kind.
     */
    Map<String, Map<Audience.Role, Boolean>> get(Collection<String> usernames) throws GuacamoleException {

        Map<String, Map<Audience.Role, Boolean>> wanted = new HashMap<>();
        if (usernames.isEmpty())
            return wanted;

        try (Connection connection = database.getConnection();
             PreparedStatement statement = connection.prepareStatement(
                 "SELECT username, " + String.join(", ", COLUMNS.values()) + " FROM pam_user_preference"
               + " WHERE username IN " + SqlDialect.parameters(usernames.size()))) {
            int index = 1;
            for (String username : usernames)
                statement.setString(index++, username);
            try (ResultSet results = statement.executeQuery()) {
                while (results.next()) {
                    Map<Audience.Role, Boolean> roles = new HashMap<>();
                    int column = 2;
                    for (Audience.Role role : COLUMNS.keySet())
                        roles.put(role, results.getBoolean(column++));
                    wanted.put(results.getString(1), roles);
                }
            }
        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to read preferences.", e);
        }

        return wanted;

    }

    /**
     * Turns one kind of email of the user on or off, keeping the others.
     *
     * @throws GuacamoleClientException
     *     If there is no such kind.
     */
    public void set(String username, String kind, boolean wanted) throws GuacamoleException {

        Audience.Role role = Audience.Role.named(kind);
        if (role == null)
            throw new GuacamoleClientException("No such kind of email.");
        String column = COLUMNS.get(role);

        Map<String, String> values = new LinkedHashMap<>();
        values.put("username", "?");
        values.put(column, "?");

        SqlDialect dialect = database.getDialect();
        try (Connection connection = database.getConnection();
             PreparedStatement statement = connection.prepareStatement(dialect.upsert("pam_user_preference",
                 Collections.singletonList("username"), values, column + " = EXCLUDED." + column))) {
            statement.setString(1, username);
            statement.setBoolean(2, wanted);
            statement.executeUpdate();
        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to save preferences.", e);
        }

    }

}
