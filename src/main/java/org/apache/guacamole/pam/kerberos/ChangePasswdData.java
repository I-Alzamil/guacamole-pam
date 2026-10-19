package org.apache.guacamole.pam.kerberos;

import org.apache.kerby.asn1.Asn1FieldInfo;
import org.apache.kerby.asn1.EnumType;
import org.apache.kerby.asn1.ExplicitField;
import org.apache.kerby.asn1.type.Asn1OctetString;
import org.apache.kerby.kerberos.kerb.type.KerberosString;
import org.apache.kerby.kerberos.kerb.type.KrbSequenceType;
import org.apache.kerby.kerberos.kerb.type.base.PrincipalName;

/**
 * The data of a set password request (RFC 3244):
 *
 * <pre>
 * ChangePasswdData ::= SEQUENCE {
 *     newpasswd  [0] OCTET STRING,
 *     targname   [1] PrincipalName OPTIONAL,
 *     targrealm  [2] Realm OPTIONAL
 * }
 * </pre>
 *
 * Only used by admins, with a target: MIT Kerberos requires one, so
 * principals changing their own password use the original protocol instead.
 */
class ChangePasswdData extends KrbSequenceType {

    private enum Field implements EnumType {
        NEW_PASSWD, TARG_NAME, TARG_REALM;

        @Override
        public int getValue() {
            return ordinal();
        }

        @Override
        public String getName() {
            return name();
        }
    }

    private static final Asn1FieldInfo[] FIELDS = new Asn1FieldInfo[] {
        new ExplicitField(Field.NEW_PASSWD, Asn1OctetString.class),
        new ExplicitField(Field.TARG_NAME, PrincipalName.class),
        new ExplicitField(Field.TARG_REALM, KerberosString.class)
    };

    ChangePasswdData() {
        super(FIELDS);
    }

    void setNewPassword(byte[] password) {
        setFieldAsOctets(Field.NEW_PASSWD, password);
    }

    void setTarget(PrincipalName name, String realm) {
        setFieldAs(Field.TARG_NAME, name);
        setFieldAs(Field.TARG_REALM, new KerberosString(realm));
    }

}
