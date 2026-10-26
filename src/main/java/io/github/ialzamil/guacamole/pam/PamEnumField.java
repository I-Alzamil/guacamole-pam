package io.github.ialzamil.guacamole.pam;

import java.util.Arrays;

import org.apache.guacamole.form.Field;

/**
 * A choice among options, shown in the order given: Guacamole's own enum
 * fields sort their options by value, which would put an insecure option
 * such as "none" among the others.
 */
public class PamEnumField extends Field {

    /**
     * Field type of these fields, rendered by the extension's own template.
     */
    public static final String TYPE = "PAM_ENUM";

    public PamEnumField(String name, String... options) {
        super(name, TYPE, Arrays.asList(options));
    }

}
