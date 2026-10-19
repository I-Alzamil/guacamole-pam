package org.apache.guacamole.pam;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.guacamole.GuacamoleClientException;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleSecurityException;
import org.apache.guacamole.GuacamoleServerException;
import org.apache.guacamole.form.Form;
import org.apache.guacamole.net.GuacamoleTunnel;
import org.apache.guacamole.net.auth.Connection;
import org.apache.guacamole.net.auth.ConnectionGroup;
import org.apache.guacamole.net.auth.DecoratingDirectory;
import org.apache.guacamole.net.auth.DelegatingConnectionGroup;
import org.apache.guacamole.net.auth.DelegatingUser;
import org.apache.guacamole.net.auth.DelegatingUserContext;
import org.apache.guacamole.net.auth.DelegatingUserGroup;
import org.apache.guacamole.net.auth.Directory;
import org.apache.guacamole.net.auth.User;
import org.apache.guacamole.net.auth.UserContext;
import org.apache.guacamole.net.auth.UserGroup;
import org.apache.guacamole.net.auth.permission.SystemPermission;
import org.apache.guacamole.pam.checkout.CheckoutService;
import org.apache.guacamole.pam.db.PasswordStore;
import org.apache.guacamole.pam.rotation.RotationService;
import org.apache.guacamole.protocol.GuacamoleClientInformation;
import org.apache.guacamole.protocol.GuacamoleConfiguration;

/**
 * Decorates the PostgreSQL UserContext: adds password management to the
 * connection editor and tracks connection usage for after-use rotation, and
 * adds the approval permission to users and user groups. Only
 * administrators may change either: users allowed to create or edit
 * connections, users or groups keep doing so, but cannot change how
 * passwords are managed, who must request access, or who approves, nor the
 * account and host of a managed connection (see {@link ProtectedFields}).
 * Balancing connection groups, which Guacamole connects through without
 * this extension's connections, refuse connections it must check. Account
 * passwords are stored encrypted when a key is set, wherever the connection
 * is saved from, and the passwords of other managed connections kept apart
 * (see {@link PasswordStore}).
 */
public class PamUserContextDecorator extends DelegatingUserContext {

    /**
     * Attributes of the approval permission.
     */
    private static final List<String> APPROVER_ATTRIBUTES = Arrays.asList(
            PamAttributes.APPROVER, PamAttributes.APPROVER_CONNECTIONS, PamAttributes.APPROVER_CONNECTION_GROUPS);

    private final RotationService rotationService;

    private final CheckoutService checkoutService;

    private final PasswordStore passwords;

    public PamUserContextDecorator(UserContext context, RotationService rotationService,
            CheckoutService checkoutService, PasswordStore passwords) {
        super(context);
        this.rotationService = rotationService;
        this.checkoutService = checkoutService;
        this.passwords = passwords;
    }

    /**
     * Prepares storing the connection's password as {@link PasswordStore}
     * decides, changing the "password" parameter to what is stored there,
     * and refuses {@link PasswordStore#TOKEN} in any other parameter, where
     * Guacamole would replace it with the password too. Returns null if the
     * connection has no configuration.
     */
    private PasswordStore.Saving preparePassword(Connection object) throws GuacamoleException {

        GuacamoleConfiguration configuration = object.getConfiguration();
        if (configuration == null)
            return null;

        for (Map.Entry<String, String> parameter : configuration.getParameters().entrySet()) {
            if (!PASSWORD_PARAMETER.equals(parameter.getKey()) && parameter.getValue() != null
                    && parameter.getValue().contains(PasswordStore.TOKEN))
                throw new GuacamoleClientException(PasswordStore.TOKEN + " can only be used as the password.");
        }

        String password = configuration.getParameter(PASSWORD_PARAMETER);
        PasswordStore.Saving saving;
        try {
            saving = passwords.prepare(toId(object.getIdentifier()), configuration.getProtocol(),
                    ProtectedFields.isManaged(object.getAttributes()), password);
        }
        catch (GuacamoleServerException e) {
            throw new GuacamoleClientException("The password cannot be saved. " + e.getMessage(), e);
        }

        if (saving.getParameter() != null && !saving.getParameter().equals(password)) {
            GuacamoleConfiguration changed = new GuacamoleConfiguration(configuration);
            changed.setParameter(PASSWORD_PARAMETER, saving.getParameter());
            object.setConfiguration(changed);
        }

        return saving;

    }

    private static Integer toId(String identifier) {
        try {
            return identifier == null ? null : Integer.valueOf(identifier);
        }
        catch (NumberFormatException e) {
            return null;
        }
    }

    /**
     * Completes storing the password of a saved connection.
     */
    private static void completePassword(PasswordStore.Saving saving, Connection object) throws GuacamoleException {
        Integer id = toId(object.getIdentifier());
        if (saving != null && id != null)
            saving.complete(id);
    }

    @Override
    public Directory<Connection> getConnectionDirectory() throws GuacamoleException {

        final Directory<Connection> connections = super.getConnectionDirectory();

        return new DecoratingDirectory<Connection>(connections) {

            @Override
            protected Connection decorate(Connection object) throws GuacamoleException {
                return new PamConnection(object, rotationService, checkoutService, passwords,
                        self().getIdentifier(), isAdministrator());
            }

            // DecoratingDirectory.add() does not go through undecorate()
            @Override
            public void add(Connection object) throws GuacamoleException {
                requireUnchanged(PamAttributes.CONNECTION_ATTRIBUTE_NAMES, null, object.getAttributes(),
                        CONNECTION_CHANGE_REFUSED);
                PasswordStore.Saving saving = preparePassword(object);
                super.add(object);
                completePassword(saving, object);
            }

            // Checked by undecorate(), then saved: only then is the password
            // kept apart
            @Override
            public void update(Connection object) throws GuacamoleException {
                PasswordStore.Saving saving = preparePassword(object);
                super.update(object);
                completePassword(saving, object);
            }

            @Override
            protected Connection undecorate(Connection object) throws GuacamoleException {
                Connection stored = object.getIdentifier() == null ? null : connections.get(object.getIdentifier());
                requireUnchanged(PamAttributes.CONNECTION_ATTRIBUTE_NAMES,
                        stored == null ? null : stored.getAttributes(), object.getAttributes(),
                        CONNECTION_CHANGE_REFUSED);

                // The account and host of a managed connection decide whose
                // password its platform rotates, and where
                if (stored != null && ProtectedFields.isManaged(stored.getAttributes())
                        && ProtectedFields.parametersChanged(ProtectedFields.MANAGED_PARAMETERS,
                                stored.getConfiguration().getParameters(), object.getConfiguration().getParameters())
                        && !isAdministrator())
                    throw new GuacamoleSecurityException(MANAGED_PARAMETERS_REFUSED);

                // Connections created through the REST API are never decorated
                if (object instanceof PamConnection)
                    return ((PamConnection) object).getUndecorated();
                return object;
            }

        };

    }

    @Override
    public Directory<ConnectionGroup> getConnectionGroupDirectory() throws GuacamoleException {

        return new DecoratingDirectory<ConnectionGroup>(super.getConnectionGroupDirectory()) {

            @Override
            protected ConnectionGroup decorate(ConnectionGroup object) {
                return new CheckedConnectionGroup(object);
            }

            @Override
            protected ConnectionGroup undecorate(ConnectionGroup object) {
                return object instanceof CheckedConnectionGroup ? ((CheckedConnectionGroup) object).getUndecorated()
                        : object;
            }

        };

    }

    /**
     * Connection group refusing to balance over connections this extension
     * checks: Guacamole opens the chosen connection itself, so its request,
     * approval and time limit would not apply, nor would its sessions be
     * tracked for rotation.
     */
    private final class CheckedConnectionGroup extends DelegatingConnectionGroup {

        CheckedConnectionGroup(ConnectionGroup group) {
            super(group);
        }

        ConnectionGroup getUndecorated() {
            return getDelegateConnectionGroup();
        }

        @Override
        public GuacamoleTunnel connect(GuacamoleClientInformation info, Map<String, String> tokens)
                throws GuacamoleException {
            if (getType() == ConnectionGroup.Type.BALANCING)
                checkoutService.requireBalanceable(getName(), getConnectionIdentifiers());
            return getDelegateConnectionGroup().connect(info, tokens);
        }

        /**
         * The deprecated variant without tokens, routed through the check
         * above as for {@link PamConnection}.
         */
        @Override
        @Deprecated
        public GuacamoleTunnel connect(GuacamoleClientInformation info) throws GuacamoleException {
            return connect(info, Collections.<String, String>emptyMap());
        }

    }

    private static final String PASSWORD_PARAMETER = "password";

    private static final String CONNECTION_CHANGE_REFUSED =
            "Only administrators can change password management or access requests.";

    private static final String MANAGED_PARAMETERS_REFUSED =
            "Only administrators can change the username, hostname or port of a connection whose password is"
            + " managed.";

    /**
     * Whether the user of this context is an administrator, determined once.
     */
    private Boolean administrator;

    private boolean isAdministrator() throws GuacamoleException {
        if (administrator == null)
            administrator = self().getEffectivePermissions().getSystemPermissions()
                    .hasPermission(SystemPermission.Type.ADMINISTER);
        return administrator;
    }

    @Override
    public Directory<User> getUserDirectory() throws GuacamoleException {

        final Directory<User> users = super.getUserDirectory();

        return new DecoratingDirectory<User>(users) {

            @Override
            protected User decorate(User object) {
                return new ApproverUser(object);
            }

            // DecoratingDirectory.add() does not go through undecorate()
            @Override
            public void add(User object) throws GuacamoleException {
                requireUnchanged(APPROVER_ATTRIBUTES, null, object.getAttributes(), APPROVER_CHANGE_REFUSED);
                super.add(object);
            }

            @Override
            protected User undecorate(User object) throws GuacamoleException {
                User stored = object.getIdentifier() == null ? null : users.get(object.getIdentifier());
                requireUnchanged(APPROVER_ATTRIBUTES, stored == null ? null : stored.getAttributes(),
                        object.getAttributes(), APPROVER_CHANGE_REFUSED);
                return object instanceof ApproverUser ? ((ApproverUser) object).getUndecorated() : object;
            }

        };

    }

    @Override
    public Directory<UserGroup> getUserGroupDirectory() throws GuacamoleException {

        final Directory<UserGroup> groups = super.getUserGroupDirectory();

        return new DecoratingDirectory<UserGroup>(groups) {

            @Override
            protected UserGroup decorate(UserGroup object) {
                return new ApproverUserGroup(object);
            }

            // DecoratingDirectory.add() does not go through undecorate()
            @Override
            public void add(UserGroup object) throws GuacamoleException {
                requireUnchanged(APPROVER_ATTRIBUTES, null, object.getAttributes(), APPROVER_CHANGE_REFUSED);
                super.add(object);
            }

            @Override
            protected UserGroup undecorate(UserGroup object) throws GuacamoleException {
                UserGroup stored = object.getIdentifier() == null ? null : groups.get(object.getIdentifier());
                requireUnchanged(APPROVER_ATTRIBUTES, stored == null ? null : stored.getAttributes(),
                        object.getAttributes(), APPROVER_CHANGE_REFUSED);
                return object instanceof ApproverUserGroup ? ((ApproverUserGroup) object).getUndecorated() : object;
            }

        };

    }

    /**
     * User exposing the approval attributes even when unset, so the editor
     * shows them for existing users as well.
     */
    private static final class ApproverUser extends DelegatingUser {

        ApproverUser(User user) {
            super(user);
        }

        User getUndecorated() {
            return getDelegateUser();
        }

        @Override
        public Map<String, String> getAttributes() {
            return withApprovalAttributes(super.getAttributes());
        }

    }

    /**
     * User group exposing the approval attributes even when unset.
     */
    private static final class ApproverUserGroup extends DelegatingUserGroup {

        ApproverUserGroup(UserGroup group) {
            super(group);
        }

        UserGroup getUndecorated() {
            return getDelegateUserGroupGroup();
        }

        @Override
        public Map<String, String> getAttributes() {
            return withApprovalAttributes(super.getAttributes());
        }

    }

    private static Map<String, String> withApprovalAttributes(Map<String, String> attributes) {
        Map<String, String> copy = new HashMap<>(attributes);
        for (String name : APPROVER_ATTRIBUTES) {
            String value = copy.get(name);
            if (value == null || value.isEmpty())
                copy.put(name, null);
        }
        return copy;
    }

    private static final String APPROVER_CHANGE_REFUSED =
            "Only administrators can change who may approve requests.";

    /**
     * Refuses a change of any of the given attributes by anyone but an
     * administrator, wherever the change comes from. Stored attributes are
     * null for a new object.
     */
    private void requireUnchanged(List<String> names, Map<String, String> stored, Map<String, String> updated,
            String refusal) throws GuacamoleException {

        if (ProtectedFields.attributesChanged(names, stored, updated) && !isAdministrator())
            throw new GuacamoleSecurityException(refusal);

    }

    @Override
    public Collection<Form> getConnectionAttributes() {
        Collection<Form> forms = new ArrayList<>(super.getConnectionAttributes());
        forms.addAll(PamAttributes.CONNECTION_FORMS);
        return Collections.unmodifiableCollection(forms);
    }

    @Override
    public Collection<Form> getUserAttributes() {
        Collection<Form> forms = new ArrayList<>(super.getUserAttributes());
        forms.addAll(PamAttributes.APPROVER_FORMS);
        return Collections.unmodifiableCollection(forms);
    }

    @Override
    public Collection<Form> getUserGroupAttributes() {
        Collection<Form> forms = new ArrayList<>(super.getUserGroupAttributes());
        forms.addAll(PamAttributes.APPROVER_FORMS);
        return Collections.unmodifiableCollection(forms);
    }

}
