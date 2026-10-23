package io.github.ialzamil.guacamole.pam.management;

import io.github.ialzamil.guacamole.pam.database.DatabaseClient;
import io.github.ialzamil.guacamole.pam.database.DatabaseTarget;
import io.github.ialzamil.guacamole.pam.rotation.ChangeOutcome;

/**
 * Changes passwords of database accounts, over the database's JDBC driver.
 */
public class DatabasePasswordChanger implements PasswordChanger {

    private final DatabaseClient database;
    private final DatabaseTarget target;

    public DatabasePasswordChanger(DatabaseClient database, DatabaseTarget target) {
        this.database = database;
        this.target = target;
    }

    @Override
    public String getCurrentPassword() {
        return target.getPassword();
    }

    @Override
    public PasswordChanger withCurrentPassword(String password) {
        return new DatabasePasswordChanger(database, target.withPassword(password));
    }

    @Override
    public ChangeOutcome change(String newPassword) {
        return database.changePassword(target, newPassword);
    }

    @Override
    public boolean accepts(String password) throws Exception {
        return database.acceptsPassword(target, password);
    }

}
