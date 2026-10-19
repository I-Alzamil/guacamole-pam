package org.apache.guacamole.pam.management;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.apache.guacamole.form.Form;

/**
 * Every available management type. New types (such as WinRM) are added here.
 */
public final class ManagementTypes {

    private static final Map<String, ManagementType> TYPES = new LinkedHashMap<>();

    static {
        register(new SshManagementType());
        register(new LdapManagementType());
        register(new KerberosManagementType());
    }

    private ManagementTypes() {
    }

    private static void register(ManagementType type) {
        TYPES.put(type.getName(), type);
    }

    /**
     * Returns the type with the given name, or null.
     */
    public static ManagementType get(String name) {
        return name == null ? null : TYPES.get(name);
    }

    public static Collection<ManagementType> all() {
        return Collections.unmodifiableCollection(TYPES.values());
    }

    /**
     * The per-connection forms of every type.
     */
    public static List<Form> getConnectionForms() {
        List<Form> forms = new ArrayList<>();
        for (ManagementType type : TYPES.values())
            forms.add(type.getConnectionForm());
        return forms;
    }

}
