package org.apache.guacamole.pam.approval;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.LinkedHashMap;
import java.util.Map;

import org.apache.guacamole.GuacamoleClientException;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleServerException;
import org.apache.guacamole.pam.db.PamDatabase;

/**
 * Which notification badges each user wants, stored in
 * "pam_user_preference": "approvals" (requests awaiting their decision) and
 * "rotations" (failed password rotations, for administrators). Each is shown
 * unless turned off.
 */
public class BadgePreferences {

    public static final String APPROVALS = "approvals";

    public static final String ROTATIONS = "rotations";

    /**
     * Column of each badge.
     */
    private static final Map<String, String> COLUMNS = new LinkedHashMap<>();

    static {
        COLUMNS.put(APPROVALS, "approval_badge");
        COLUMNS.put(ROTATIONS, "rotation_badge");
    }

    private final PamDatabase database;

    public BadgePreferences(PamDatabase database) {
        this.database = database;
    }

    /**
     * Whether the user wants each badge, by name.
     */
    public Map<String, Boolean> get(String username) throws GuacamoleException {

        Map<String, Boolean> shown = new LinkedHashMap<>();
        for (String badge : COLUMNS.keySet())
            shown.put(badge, true);

        try (Connection connection = database.getConnection();
             PreparedStatement statement = connection.prepareStatement(
                 "SELECT " + String.join(", ", COLUMNS.values()) + " FROM pam_user_preference WHERE username = ?")) {
            statement.setString(1, username);
            try (ResultSet results = statement.executeQuery()) {
                if (results.next()) {
                    int column = 1;
                    for (String badge : COLUMNS.keySet())
                        shown.put(badge, results.getBoolean(column++));
                }
            }
        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to read preferences.", e);
        }

        return shown;

    }

    /**
     * Turns one badge of the user on or off, keeping the others.
     *
     * @throws GuacamoleClientException
     *     If there is no such badge.
     */
    public void set(String username, String badge, boolean shown) throws GuacamoleException {

        String column = COLUMNS.get(badge);
        if (column == null)
            throw new GuacamoleClientException("No such badge.");

        try (Connection connection = database.getConnection();
             PreparedStatement statement = connection.prepareStatement(
                 "INSERT INTO pam_user_preference (username, " + column + ") VALUES (?, ?)"
               + " ON CONFLICT (username) DO UPDATE SET " + column + " = EXCLUDED." + column)) {
            statement.setString(1, username);
            statement.setBoolean(2, shown);
            statement.executeUpdate();
        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to save preferences.", e);
        }

    }

}
