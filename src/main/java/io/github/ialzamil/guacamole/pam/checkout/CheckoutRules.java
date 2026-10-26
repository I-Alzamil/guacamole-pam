package io.github.ialzamil.guacamole.pam.checkout;

import org.apache.guacamole.GuacamoleClientException;
import org.apache.guacamole.GuacamoleException;

import io.github.ialzamil.guacamole.pam.AccountProtocol;
import io.github.ialzamil.guacamole.pam.PamAttributes;
import io.github.ialzamil.guacamole.pam.db.ConnectionRepository.Target;
import io.github.ialzamil.guacamole.pam.management.ManagementType;
import io.github.ialzamil.guacamole.pam.management.ManagementTypes;
import io.github.ialzamil.guacamole.pam.platform.Platform;
import io.github.ialzamil.guacamole.pam.platform.PlatformRepository;
import io.github.ialzamil.guacamole.pam.settings.PamSettings;

/**
 * What each connection allows of requests and checkouts, as its attributes
 * say, or else the shared settings: whether it needs a request and how many
 * approvals, for how long it is held, by one holder or several, and how its
 * checkouts may be extended.
 */
public final class CheckoutRules {

    private final PlatformRepository platforms;

    /**
     * Settings shared by every server: whether administrators bypass
     * requests, and how checkouts may be extended unless a connection says
     * otherwise.
     */
    private final PamSettings settings;

    CheckoutRules(PlatformRepository platforms, PamSettings settings) {
        this.platforms = platforms;
        this.settings = settings;
    }

    public static final int DEFAULT_MINUTES = 60;

    public static final int MAX_MINUTES = 7 * 24 * 60;

    /**
     * Upper bound of the extensions a connection can allow, as of the
     * setting {@link PamSettings#MAX_EXTENSIONS}.
     */
    static final int MAX_EXTENSIONS = PamSettings.MAX_EXTENSIONS.getMaximum();

    static final int MAX_REASON_LENGTH = 500;

    /**
     * How far ahead access can be requested, in days.
     */
    public static final int MAX_DAYS_AHEAD = 30;

    /**
     * How long before now a start of access requested ahead of time may be,
     * in milliseconds, so a start picked in the current minute is accepted.
     */
    static final long START_TOLERANCE_MS = 60000;

    /**
     * Upper bound of the approvals a connection can require.
     */
    static final int MAX_APPROVALS = 10;

    static String validateReason(String reason) throws GuacamoleClientException {
        String trimmed = reason == null ? "" : reason.trim();
        if (trimmed.isEmpty())
            throw new GuacamoleClientException("Please give a reason for your request.");
        if (trimmed.length() > MAX_REASON_LENGTH)
            throw new GuacamoleClientException("The reason is limited to " + MAX_REASON_LENGTH + " characters.");
        return trimmed;
    }

    /**
     * Refuses a start of access requested ahead of time that is past, or too
     * far ahead.
     */
    static void validateStart(long starts) throws GuacamoleClientException {
        long now = System.currentTimeMillis();
        if (starts < now - START_TOLERANCE_MS)
            throw new GuacamoleClientException("Please choose a start in the future.");
        if (starts > now + MAX_DAYS_AHEAD * 24L * 3600000L)
            throw new GuacamoleClientException("Access can be requested up to " + MAX_DAYS_AHEAD + " days ahead.");
    }

    /**
     * Whether the user, an administrator or not, connects and checks out
     * without a request.
     */
    boolean bypassesRequests(boolean administrator) throws GuacamoleException {
        return administrator && settings.isAdminBypassRequests();
    }

    /**
     * Whether the connection is an Account, checked out for its password.
     */
    public static boolean isAccount(Target target) {
        return AccountProtocol.NAME.equals(target.getProtocol());
    }

    /**
     * Whether the holder of a checkout of the connection, not an Account,
     * may see its password.
     */
    public static boolean revealsPassword(Target target) {
        return !isAccount(target) && "true".equals(target.getAttribute(PamAttributes.REVEAL_PASSWORD));
    }

    /**
     * Whether users must request the connection, with a reason: always,
     * unless it allows access without a request. Connections requiring
     * approvals always require a request. The same applies to Accounts and
     * to other connections.
     */
    public static boolean requiresRequest(Target target) {
        return !"true".equals(target.getAttribute(PamAttributes.REQUEST_EXEMPT))
            || getApprovalsRequired(target) > 0;
    }

    /**
     * Whether the connection goes through checkouts: when it requires a
     * request, and always for Accounts, whose password is only ever shown
     * through a checkout (without a request, one is started as soon as the
     * Account is opened).
     */
    public static boolean isRequestable(Target target) {
        return isAccount(target) || requiresRequest(target);
    }

    /**
     * How many distinct approvers must approve a request for the connection.
     */
    static int getApprovalsRequired(Target target) {
        try {
            return Math.max(0, Math.min(MAX_APPROVALS, Integer.parseInt(target.getAttribute(PamAttributes.APPROVALS_REQUIRED))));
        }
        catch (NumberFormatException | NullPointerException e) {
            return 0;
        }
    }

    Platform platformOf(Target target) throws GuacamoleException {
        return platforms.get(target.getAttribute(PamAttributes.PLATFORM));
    }

    /**
     * Extra identification of the account given by its platform's type,
     * such as its LDAP DN, or null.
     */
    static String accountDetail(Target target, Platform platform) {
        ManagementType type = platform == null ? null : ManagementTypes.get(platform.getType());
        return type == null ? null : type.getAccountDetail(target, platform);
    }

    /**
     * Whether this extension manages (rotates) the password of the connection.
     */
    public static boolean isManaged(Target target) {
        return target.getAttribute(PamAttributes.PLATFORM) != null;
    }

    /**
     * Whether checkouts of the connection exclude other holders. Defaults to
     * exclusive for managed connections, whose password changes on release.
     */
    public static boolean isExclusive(Target target) {
        String value = target.getAttribute(PamAttributes.CHECKOUT_EXCLUSIVE);
        if (PamAttributes.EXCLUSIVE_YES.equals(value))
            return true;
        if (PamAttributes.EXCLUSIVE_NO.equals(value))
            return false;
        return isManaged(target);
    }

    static String accountName(Target target) {
        return target.getParameters().get(AccountProtocol.USERNAME);
    }

    /**
     * Whether holders may extend their checkouts of the connection: as it
     * says, or as "pam-extensions-enabled" says.
     */
    boolean allowsExtensions(Target target) throws GuacamoleException {
        String value = target.getAttribute(PamAttributes.EXTENSIONS);
        if (PamAttributes.EXTENSIONS_YES.equals(value))
            return true;
        if (PamAttributes.EXTENSIONS_NO.equals(value))
            return false;
        return settings.isExtensionsEnabled();
    }

    /**
     * How many times a checkout of the connection may be extended in all: 0
     * if it allows no extensions.
     */
    int getMaxExtensions(Target target) throws GuacamoleException {
        if (!allowsExtensions(target))
            return 0;
        try {
            return Math.max(0, Math.min(MAX_EXTENSIONS, Integer.parseInt(target.getAttribute(PamAttributes.MAX_EXTENSIONS))));
        }
        catch (NumberFormatException | NullPointerException e) {
            return settings.getMaxExtensions();
        }
    }

    /**
     * How many times its time limit a request for the connection may ask
     * for at once: one more than the extensions it allows.
     */
    int getMaxPeriods(Target target) throws GuacamoleException {
        return 1 + getMaxExtensions(target);
    }

    /**
     * By how many minutes an extension extends a checkout of the connection.
     */
    static int getExtensionMinutes(Target target) {
        try {
            int minutes = Integer.parseInt(target.getAttribute(PamAttributes.EXTENSION_DURATION));
            return Math.max(1, Math.min(MAX_MINUTES, minutes));
        }
        catch (NumberFormatException | NullPointerException e) {
            return getDuration(target);
        }
    }

    static int getDuration(Target target) {
        try {
            int minutes = Integer.parseInt(target.getAttribute(PamAttributes.CHECKOUT_DURATION));
            return Math.max(1, Math.min(MAX_MINUTES, minutes));
        }
        catch (NumberFormatException | NullPointerException e) {
            return DEFAULT_MINUTES;
        }
    }

}
