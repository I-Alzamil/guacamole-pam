package io.github.ialzamil.guacamole.pam;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

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
import org.apache.guacamole.protocol.GuacamoleClientInformation;
import org.apache.guacamole.protocol.GuacamoleConfiguration;

import io.github.ialzamil.guacamole.pam.approval.ApproverDirectory;
import io.github.ialzamil.guacamole.pam.checkout.CheckoutService;
import io.github.ialzamil.guacamole.pam.db.ConnectionRepository;
import io.github.ialzamil.guacamole.pam.db.ConnectionSecrets;
import io.github.ialzamil.guacamole.pam.rotation.RotationService;

/**
 * Decorates the UserContext of the managed data source (PostgreSQL, MySQL or
 * SQL Server): adds password management to the connection editor and tracks
 * connection usage for after-use rotation, and adds the approval permission
 * to users and user groups. Only
 * administrators may change either: users allowed to create or edit
 * connections, users or groups keep doing so, but cannot change how
 * passwords are managed, who must request access, or who approves, nor the
 * account and host of a managed connection (see {@link ProtectedFields}).
 * Balancing connection groups, through which Guacamole opens a connection
 * without going through this extension, refuse to balance over connections
 * it must check. Wherever a connection is saved from, its passwords and keys
 * are kept apart, encrypted, when a key is set (see
 * {@link ConnectionSecrets}).
 */
public class PamUserContextDecorator extends DelegatingUserContext {

    /**
     * Attributes of the approval permission.
     */
    private static final List<String> APPROVER_ATTRIBUTES = ApproverDirectory.APPROVAL_ATTRIBUTES;

    private final RotationService rotationService;

    private final CheckoutService checkoutService;

    private final ConnectionSecrets connectionSecrets;

    public PamUserContextDecorator(UserContext context, RotationService rotationService,
            CheckoutService checkoutService, ConnectionSecrets connectionSecrets) {
        super(context);
        this.rotationService = rotationService;
        this.checkoutService = checkoutService;
        this.connectionSecrets = connectionSecrets;
    }

    /**
     * Prepares storing the connection's sensitive parameters as
     * {@link ConnectionSecrets} decides, changing them to what is stored in
     * them. Returns null if the connection has no configuration.
     */
    private ConnectionSecrets.Saving prepareSecrets(Connection object) throws GuacamoleException {

        GuacamoleConfiguration configuration = object.getConfiguration();
        if (configuration == null)
            return null;

        ConnectionSecrets.Saving saving;
        try {
            saving = connectionSecrets.prepare(Values.parseId(object.getIdentifier()), configuration.getProtocol(),
                    configuration.getParameters());
        }
        catch (GuacamoleServerException e) {
            throw new GuacamoleClientException("The connection cannot be saved. " + e.getMessage(), e);
        }

        if (!saving.getChanges().isEmpty()) {
            GuacamoleConfiguration changed = new GuacamoleConfiguration(configuration);
            for (Map.Entry<String, String> change : saving.getChanges().entrySet()) {
                if (change.getValue() == null)
                    changed.unsetParameter(change.getKey());
                else
                    changed.setParameter(change.getKey(), change.getValue());
            }
            object.setConfiguration(changed);
        }

        return saving;

    }

    /**
     * Completes storing the sensitive parameters of a saved connection.
     */
    private static void completeSecrets(ConnectionSecrets.Saving saving, Connection object)
            throws GuacamoleException {
        Integer id = Values.parseId(object.getIdentifier());
        if (saving != null && id != null)
            saving.complete(id);
    }

    @Override
    public Directory<Connection> getConnectionDirectory() throws GuacamoleException {

        final Directory<Connection> connections = super.getConnectionDirectory();

        return new DecoratingDirectory<Connection>(connections) {

            @Override
            protected Connection decorate(Connection object) throws GuacamoleException {
                return new PamConnection(object, rotationService, checkoutService, connectionSecrets,
                        PamUserContextDecorator.this);
            }

            // DecoratingDirectory.add() does not go through undecorate()
            @Override
            public void add(Connection object) throws GuacamoleException {
                requireUnchanged(PamAttributes.CONNECTION_ATTRIBUTE_NAMES, null, object.getAttributes(),
                        CONNECTION_CHANGE_REFUSED);
                ConnectionSecrets.Saving saving = prepareSecrets(object);
                super.add(object);
                completeSecrets(saving, object);
            }

            // Checked first: preparing the secrets puts the token, shown as
            // the mask, in place of a new value, which would then look
            // unchanged
            @Override
            public void update(Connection object) throws GuacamoleException {
                requireAllowedChanges(object);
                ConnectionSecrets.Saving saving = prepareSecrets(object);
                super.update(object);
                completeSecrets(saving, object);
            }

            // Its checkouts and pending requests end with it; their rows
            // stay, as the audit log
            @Override
            public void remove(String identifier) throws GuacamoleException {
                CheckoutService.Deletion deletion = checkoutService.prepareDeletion(identifier);
                super.remove(identifier);
                deletion.complete(self().getIdentifier());
            }

            /**
             * Refuses changes only administrators may make: this
             * extension's attributes, and what ProtectedFields protects
             * on managed connections.
             */
            private void requireAllowedChanges(Connection object) throws GuacamoleException {

                Connection stored = object.getIdentifier() == null ? null : connections.get(object.getIdentifier());
                requireUnchanged(PamAttributes.CONNECTION_ATTRIBUTE_NAMES,
                        stored == null ? null : stored.getAttributes(), object.getAttributes(),
                        CONNECTION_CHANGE_REFUSED);

                // Compared as the editor sees both, where a kept secret is
                // the mask
                Integer id = Values.parseId(object.getIdentifier());
                if (stored != null && id != null && ProtectedFields.isManaged(stored.getAttributes())
                        && (ProtectedFields.managedParametersChanged(
                                ConnectionSecrets.masked(stored.getConfiguration(), id).getParameters(),
                                ConnectionSecrets.masked(object.getConfiguration(), id).getParameters())
                            || ProtectedFields.attributesChanged(ProtectedFields.MANAGED_ATTRIBUTES,
                                stored.getAttributes(), object.getAttributes())
                            || !Objects.equals(stored.getConfiguration().getProtocol(),
                                object.getConfiguration().getProtocol()))
                        && !isAdministrator())
                    throw new GuacamoleSecurityException(MANAGED_PARAMETERS_REFUSED);

                // Approvers may be given by connection group
                if (stored != null && !Objects.equals(stored.getParentIdentifier(), object.getParentIdentifier())
                        && ConnectionRepository.needsApproval(stored.getAttributes().get(PamAttributes.APPROVALS_REQUIRED))
                        && !isAdministrator())
                    throw new GuacamoleSecurityException(MOVE_REFUSED);

            }

            @Override
            protected Connection undecorate(Connection object) throws GuacamoleException {
                // Connections created through the REST API are never decorated
                if (object instanceof PamConnection)
                    return ((PamConnection) object).getUndecorated();
                return object;
            }

        };

    }

    @Override
    public Directory<ConnectionGroup> getConnectionGroupDirectory() throws GuacamoleException {

        final Directory<ConnectionGroup> groups = super.getConnectionGroupDirectory();

        return new DecoratingDirectory<ConnectionGroup>(groups) {

            @Override
            protected ConnectionGroup decorate(ConnectionGroup object) {
                return new CheckedConnectionGroup(object);
            }

            // Moving a group moves the connections within it, whose
            // approvers may be given by connection group
            @Override
            public void update(ConnectionGroup object) throws GuacamoleException {
                ConnectionGroup stored = object.getIdentifier() == null ? null : groups.get(object.getIdentifier());
                if (stored != null && !Objects.equals(stored.getParentIdentifier(), object.getParentIdentifier())
                        && !isAdministrator() && checkoutService.anyNeedsApprovalWithin(object.getIdentifier()))
                    throw new GuacamoleSecurityException(MOVE_REFUSED);
                super.update(object);
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
     * tracked for rotation. For the same reason, it is given the secrets of
     * all its connections, each standing for its own token.
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
            if (getType() != ConnectionGroup.Type.BALANCING)
                return getDelegateConnectionGroup().connect(info, tokens);

            // All of them, not only those the user may read: Guacamole
            // balances over them all
            List<String> balanced = checkoutService.listBalanced(getIdentifier());
            checkoutService.requireBalanceable(getName(), balanced);

            // Guacamole shows users no detail of a server error, only logs it
            Map<String, String> withSecrets = new HashMap<>(tokens);
            for (String identifier : balanced) {
                Integer id = Values.parseId(identifier);
                try {
                    if (id != null)
                        withSecrets.putAll(connectionSecrets.getTokens(id));
                }
                catch (GuacamoleServerException e) {
                    throw new GuacamoleServerException("Connection group \"" + getName() + "\" cannot be opened: "
                            + e.getMessage(), e);
                }
            }

            return getDelegateConnectionGroup().connect(info, withSecrets);
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

    private static final String CONNECTION_CHANGE_REFUSED =
            "Only administrators can change password management or access requests.";

    private static final String MOVE_REFUSED =
            "Only administrators can move a connection requiring approval, or a group containing one: its group"
            + " may decide who approves it.";

    private static final String MANAGED_PARAMETERS_REFUSED =
            "Only administrators can change the credentials of a connection whose password is managed, where it"
            + " connects (hostname, port, gateway, SFTP or repeater), how it checks the server (host key or"
            + " certificates), what it runs as the account (command, initial program or RemoteApp), its"
            + " protocol or its guacd.";

    /**
     * Whether the user of this context is an administrator now: read again
     * each time, so revoking it takes effect at once.
     */
    boolean isAdministrator() throws GuacamoleException {
        return self().getEffectivePermissions().getSystemPermissions()
                .hasPermission(SystemPermission.Type.ADMINISTER);
    }

    /**
     * Whether the user may still use a connection they opened a session
     * of: they may still read it, and hold the checkout it requires (or, as
     * an administrator, bypass requests). Asked of the database again, so a
     * revoked permission is seen.
     */
    boolean mayStillUse(String identifier) throws GuacamoleException {

        if (getDelegateUserContext().getConnectionDirectory().get(identifier) == null)
            return false;

        return checkoutService.mayKeepSession(identifier, self().getIdentifier(), isAdministrator());

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
