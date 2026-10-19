package org.apache.guacamole.pam;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.apache.guacamole.form.BooleanField;
import org.apache.guacamole.form.EnumField;
import org.apache.guacamole.form.Field;
import org.apache.guacamole.form.Form;
import org.apache.guacamole.form.NumericField;
import org.apache.guacamole.form.TextField;
import org.apache.guacamole.pam.management.ManagementTypes;
import org.apache.guacamole.pam.platform.Platform;

/**
 * Connection attributes added by this extension: the "Password management"
 * of every connection. The web UI shows only the sections that apply:
 * policy and type sections only for managed connections, the section of the
 * platform's type only, and checkout settings only for Account connections.
 */
public final class PamAttributes {

    /**
     * Identifier of the platform managing the password. Empty means the
     * password is stored only.
     */
    public static final String PLATFORM = "pam-platform";

    /**
     * Overrides of the platform policy. Empty means the platform's value.
     */
    public static final String ROTATION_MODE = "pam-rotation-mode";
    public static final String ROTATION_INTERVAL = "pam-rotation-interval";
    public static final String PASSWORD_LENGTH = "pam-password-length";

    /**
     * How long, in minutes, a requested password stays checked out before it
     * is released automatically. Applies to Account connections.
     */
    public static final String CHECKOUT_DURATION = "pam-checkout-duration";

    /**
     * Whether a checked out password excludes every other holder: "" for
     * the default (exclusive only when the account is managed), "yes" or "no".
     */
    public static final String CHECKOUT_EXCLUSIVE = "pam-checkout-exclusive";
    public static final String EXCLUSIVE_YES = "yes";
    public static final String EXCLUSIVE_NO = "no";

    /**
     * "true" if users may connect without requesting access. Otherwise
     * (the default) users must request access, and receive a time-limited
     * checkout, before connecting. Account connections always require a
     * request, and so does a connection requiring approvals.
     */
    public static final String REQUEST_EXEMPT = "pam-request-exempt";

    /**
     * How many distinct approvers must approve a request before
     * its checkout starts. Empty or 0 means no approval is needed.
     */
    public static final String APPROVALS_REQUIRED = "pam-approvals-required";

    /**
     * User and user group attribute: "true" if the user, or every member of
     * the group, may approve requests, for the connections listed
     * in {@link #APPROVER_CONNECTIONS}. Administrators may approve any
     * request. Only administrators can change these attributes.
     */
    public static final String APPROVER = "pam-approver";

    /**
     * User and user group attribute: JSON array of the identifiers of the
     * connections whose requests the user or group members may approve.
     */
    public static final String APPROVER_CONNECTIONS = "pam-approver-connections";

    /**
     * User and user group attribute: JSON array of the identifiers of
     * connection groups; requests of every connection within them, at any
     * depth, may be approved.
     */
    public static final String APPROVER_CONNECTION_GROUPS = "pam-approver-connection-groups";

    /**
     * The approval permission of users and user groups. Declared so that
     * Guacamole accepts and stores the attributes; the web UI shows them in
     * the permissions section rather than with the other attributes.
     */
    public static final List<Form> APPROVER_FORMS = Collections.singletonList(
        new Form("pam-approval", Arrays.<Field>asList(
            new BooleanField(APPROVER, "true"),
            new TextField(APPROVER_CONNECTIONS),
            new TextField(APPROVER_CONNECTION_GROUPS)
        ))
    );

    /**
     * Custom field type rendering a drop-down of platforms.
     */
    public static final String PLATFORM_FIELD_TYPE = "PAM_PLATFORM";

    /**
     * Every form of the password management of a connection.
     */
    public static final List<Form> CONNECTION_FORMS;

    /**
     * Names of every attribute of {@link #CONNECTION_FORMS}. They decide how
     * a connection's password is managed and who may use it, so only
     * administrators may change them.
     */
    public static final List<String> CONNECTION_ATTRIBUTE_NAMES;

    static {

        List<Form> forms = new ArrayList<>();

        forms.add(new Form("pam-management", Collections.<Field>singletonList(
            new Field(PLATFORM, PLATFORM_FIELD_TYPE)
        )));

        forms.add(new Form("pam-policy", Arrays.<Field>asList(
            new EnumField(ROTATION_MODE, Arrays.asList("", Platform.MODE_NEVER,
                    Platform.MODE_AFTER_USE, Platform.MODE_PERIODIC)),
            new NumericField(ROTATION_INTERVAL),
            new NumericField(PASSWORD_LENGTH)
        )));

        forms.addAll(ManagementTypes.getConnectionForms());

        forms.add(new Form("pam-checkout", Arrays.<Field>asList(
            new BooleanField(REQUEST_EXEMPT, "true"),
            new NumericField(CHECKOUT_DURATION),
            new EnumField(CHECKOUT_EXCLUSIVE, Arrays.asList("", EXCLUSIVE_YES, EXCLUSIVE_NO)),
            new NumericField(APPROVALS_REQUIRED)
        )));

        CONNECTION_FORMS = Collections.unmodifiableList(forms);

        List<String> names = new ArrayList<>();
        for (Form form : CONNECTION_FORMS) {
            for (Field field : form.getFields())
                names.add(field.getName());
        }
        CONNECTION_ATTRIBUTE_NAMES = Collections.unmodifiableList(names);

    }

    private PamAttributes() {
    }

}
