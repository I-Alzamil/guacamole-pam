package io.github.ialzamil.guacamole.pam;

import java.util.Arrays;

import org.apache.guacamole.form.Field;
import org.apache.guacamole.form.Form;
import org.apache.guacamole.form.MultilineField;
import org.apache.guacamole.form.PasswordField;
import org.apache.guacamole.form.TextField;
import org.apache.guacamole.form.UsernameField;
import org.apache.guacamole.protocols.ProtocolInfo;

/**
 * The "pam-account" connection type: an account whose password users
 * request instead of opening a remote session. Whether and how its password
 * is managed is set, as for any connection, by its platform.
 */
public final class AccountProtocol {

    public static final String NAME = "pam-account";

    public static final String USERNAME = "username";
    public static final String PASSWORD = "password";

    /**
     * Optional address where the account is used, shown when requesting.
     */
    public static final String URL = "account-url";

    /**
     * Optional notes shown when requesting.
     */
    public static final String NOTES = "account-notes";

    public static final ProtocolInfo PROTOCOL = new ProtocolInfo(NAME, Arrays.asList(
        new Form("account", Arrays.<Field>asList(
            new UsernameField(USERNAME),
            new PasswordField(PASSWORD),
            new TextField(URL),
            new MultilineField(NOTES)
        ))
    ));

    private AccountProtocol() {
    }

}
