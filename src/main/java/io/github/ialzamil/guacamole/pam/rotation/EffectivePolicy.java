package io.github.ialzamil.guacamole.pam.rotation;

import io.github.ialzamil.guacamole.pam.PamAttributes;
import io.github.ialzamil.guacamole.pam.db.ConnectionRepository.Target;
import io.github.ialzamil.guacamole.pam.platform.Platform;

/**
 * The rotation policy applying to a connection: its own overrides where
 * set, otherwise its platform's policy, otherwise the defaults.
 */
public final class EffectivePolicy {

    private final String mode;
    private final Integer intervalHours;
    private final String passwordPolicy;

    private EffectivePolicy(String mode, Integer intervalHours, String passwordPolicy) {
        this.mode = mode;
        this.intervalHours = intervalHours;
        this.passwordPolicy = passwordPolicy;
    }

    /**
     * Resolves the policy of a connection. A connection without platform is
     * never rotated.
     */
    public static EffectivePolicy of(Platform platform, Target target) {

        if (platform == null)
            return new EffectivePolicy(Platform.MODE_NEVER, null, null);

        String mode = first(target.getAttribute(PamAttributes.ROTATION_MODE),
                platform.getPolicy().get(Platform.POLICY_ROTATION_MODE), Platform.MODE_NEVER);

        Integer interval = parse(first(target.getAttribute(PamAttributes.ROTATION_INTERVAL),
                platform.getPolicy().get(Platform.POLICY_ROTATION_INTERVAL), null));

        String passwordPolicy = first(target.getAttribute(PamAttributes.PASSWORD_POLICY),
                platform.getPolicy().get(Platform.POLICY_PASSWORD_POLICY), null);

        return new EffectivePolicy(mode, interval, passwordPolicy);

    }

    /**
     * "never", "after-use" or "periodic".
     */
    public String getMode() {
        return mode;
    }

    /**
     * Hours between periodic rotations, or null if not set.
     */
    public Integer getIntervalHours() {
        return intervalHours;
    }

    /**
     * Identifier of the password policy of new passwords, or null for the
     * default rules.
     */
    public String getPasswordPolicy() {
        return passwordPolicy;
    }

    private static String first(String override, String platformValue, String fallback) {
        if (override != null && !override.trim().isEmpty())
            return override.trim();
        if (platformValue != null && !platformValue.trim().isEmpty())
            return platformValue.trim();
        return fallback;
    }

    private static Integer parse(String value) {
        try {
            return value == null ? null : Integer.valueOf(value);
        }
        catch (NumberFormatException e) {
            return null;
        }
    }

}
