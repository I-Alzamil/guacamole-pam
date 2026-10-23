package io.github.ialzamil.guacamole.pam.db;

import org.apache.guacamole.GuacamoleServerException;

/**
 * Thrown while the extension's tables could not be created. The reason, and
 * how to fix it, is logged once when it is first found, so callers retrying
 * regularly (the background checks) need not log it again.
 */
public class SchemaUnavailableException extends GuacamoleServerException {

    private static final long serialVersionUID = 1L;

    public SchemaUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }

}
