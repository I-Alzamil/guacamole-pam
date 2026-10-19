package org.apache.guacamole.pam.kerberos;

import static org.junit.Assert.assertEquals;

import java.nio.charset.StandardCharsets;

import org.apache.kerby.kerberos.kerb.KrbCodec;
import org.apache.kerby.kerberos.kerb.type.base.NameType;
import org.apache.kerby.kerberos.kerb.type.base.PrincipalName;
import org.junit.Test;

/**
 * The set password request data of RFC 3244. The expected encoding was
 * computed independently, from the ASN.1 definitions of RFC 3244 and RFC
 * 4120 (DER, Python).
 */
public class ChangePasswdDataTest {

    @Test
    public void encodesPasswordAndTarget() throws Exception {

        ChangePasswdData data = new ChangePasswdData();
        data.setNewPassword("New-Pw1!".getBytes(StandardCharsets.UTF_8));
        data.setTarget(new PrincipalName("alice", NameType.NT_PRINCIPAL), "EXAMPLE.ORG");

        StringBuilder hex = new StringBuilder();
        for (byte b : KrbCodec.encode(data))
            hex.append(String.format("%02x", b));

        assertEquals("302fa00a04084e65772d50773121a1123010a003020101a10930071b05616c696365a20d1b0b4558414d504c452e4f5247",
                hex.toString());

    }

}
