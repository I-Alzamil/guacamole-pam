package io.github.ialzamil.guacamole.pam.ha;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.net.auth.User;
import org.apache.guacamole.net.auth.UserContext;

/**
 * Whether the database account of a user may be used now, as Guacamole's
 * database authentication decides at login: not disabled, within its
 * validity dates, and within its access window. A login built again on
 * another server is refused if not, as logging in again would be: given a
 * login it did not make itself, that authentication checks validity dates
 * and access windows only if "<database>-user-required" is set, and turns a
 * disabled account into one without permissions rather than refusing it.
 *
 * The dates and windows are checked by the account itself, as Guacamole's
 * database authentication (ModeledUser, as of Guacamole 1.6.0) checks them,
 * with the account's time zone: by reflection, as it is not part of
 * Guacamole's extension API. An account that cannot be checked is refused.
 */
final class Accounts {

    private Accounts() {
    }

    /**
     * Why the database account of the given user may not be used now, or
     * null if it may, or the user has none.
     *
     * @param context
     *     The context Guacamole's database authentication gave the user,
     *     not decorated.
     */
    static String refusal(UserContext context, Database database, String username) throws GuacamoleException {

        User self = context.self();
        try {
            if (is(self, "isSkeleton"))
                return isDisabled(database, username) ? "the account is disabled" : null;
            if (is(self, "isDisabled"))
                return "the account is disabled";
            if (!is(self, "isAccountValid"))
                return "the account is no longer valid";
            if (!is(self, "isAccountAccessible"))
                return "the account may not be used at this time";
            return null;
        }
        catch (ReflectiveOperationException | RuntimeException e) {
            return "the account could not be checked (" + e + ")";
        }
        catch (SQLException e) {
            return "the account could not be read: " + e.getMessage();
        }

    }

    private static boolean is(User user, String method) throws ReflectiveOperationException {
        Method check = user.getClass().getMethod(method);
        try {
            return (Boolean) check.invoke(user);
        }
        catch (InvocationTargetException e) {
            if (e.getCause() instanceof RuntimeException)
                throw (RuntimeException) e.getCause();
            throw e;
        }
    }

    /**
     * Whether the user has a disabled account: Guacamole's database
     * authentication gives such a user an account without permissions
     * ("skeleton"), as it gives users who have none.
     */
    private static boolean isDisabled(Database database, String username) throws SQLException {
        try (Connection connection = database.connect();
             PreparedStatement statement = connection.prepareStatement("SELECT u.disabled FROM guacamole_user u"
                 + " JOIN guacamole_entity e ON u.entity_id = e.entity_id WHERE e.name = ? AND e.type = 'USER'")) {
            statement.setString(1, username);
            try (ResultSet results = statement.executeQuery()) {
                return results.next() && results.getBoolean(1);
            }
        }
    }

}
