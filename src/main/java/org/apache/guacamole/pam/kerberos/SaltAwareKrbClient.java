package org.apache.guacamole.pam.kerberos;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;

import org.apache.kerby.kerberos.kerb.KrbCodec;
import org.apache.kerby.kerberos.kerb.KrbErrorCode;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.client.KrbContext;
import org.apache.kerby.kerberos.kerb.client.KrbSetting;
import org.apache.kerby.kerberos.kerb.client.impl.DefaultInternalKrbClient;
import org.apache.kerby.kerberos.kerb.client.request.AsRequest;
import org.apache.kerby.kerberos.kerb.client.request.AsRequestWithPasswd;
import org.apache.kerby.kerberos.kerb.crypto.EncryptionHandler;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionType;
import org.apache.kerby.kerberos.kerb.type.base.EtypeInfo2;
import org.apache.kerby.kerberos.kerb.type.base.EtypeInfo2Entry;
import org.apache.kerby.kerberos.kerb.type.base.KrbError;
import org.apache.kerby.kerberos.kerb.type.base.KrbMessage;
import org.apache.kerby.kerberos.kerb.type.base.MethodData;
import org.apache.kerby.kerberos.kerb.type.pa.PaDataEntry;
import org.apache.kerby.kerberos.kerb.type.pa.PaDataType;
import org.apache.kerby.kerberos.kerb.type.ticket.TgtTicket;

/**
 * Kerby's client, deriving password keys with the salt the KDC advertises
 * (PA-ETYPE-INFO2) instead of always the default one (realm and principal
 * name). Kerby keeps only the encryption types of the KDC's demand for
 * pre-authentication, not its salts. Active Directory gives some accounts
 * another salt, such as the built-in Administrator of a server promoted to
 * domain controller (salted with the former computer name), or renamed
 * accounts until their next password change; without the KDC's salt their
 * passwords are refused.
 *
 * The salt is learned from the KDC's answer to the same request without
 * pre-authentication, which is not a failed login (it cannot lock the
 * account out).
 */
class SaltAwareKrbClient extends DefaultInternalKrbClient {

    private static final int MAX_REPLY_LENGTH = 64 * 1024;

    SaltAwareKrbClient(KrbSetting setting) {
        super(setting);
    }

    @Override
    protected TgtTicket doRequestTgt(AsRequest request) throws KrbException {

        if (request instanceof AsRequestWithPasswd && !(request instanceof SaltAwareAsRequest)) {
            SaltAwareAsRequest saltAware = new SaltAwareAsRequest(request.getContext());
            copy(request, saltAware);
            saltAware.advertised = advertisedKeys(request);
            request = saltAware;
        }

        return super.doRequestTgt(request);

    }

    private static void copy(AsRequest from, AsRequest to) {
        to.setClientPrincipal(from.getClientPrincipal());
        to.setServerPrincipal(from.getServerPrincipal());
        to.setRequestOptions(from.getRequestOptions());
    }

    /**
     * The KDC's encryption types and salts for the client, from its answer
     * to the request without pre-authentication, or null if it sent none
     * (the request then goes ahead with the default salt).
     */
    private EtypeInfo2 advertisedKeys(AsRequest request) throws KrbException {

        // Without pre-authentication data, so the KDC asks for it (with its
        // salts) instead of counting a failed login
        AsRequestWithPasswd probe = new AsRequestWithPasswd(request.getContext());
        copy(request, probe);
        probe.setPreauthRequired(false);
        probe.process();
        probe.getKdcReq().setPaData(null);
        byte[] message = KrbCodec.encode(probe.getKdcReq());

        KrbSetting setting = getSetting();
        byte[] reply;
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(setting.getKdcHost(), setting.getKdcTcpPort()), setting.getTimeout());
            socket.setSoTimeout(setting.getTimeout());
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            out.writeInt(message.length);
            out.write(message);
            out.flush();
            DataInputStream in = new DataInputStream(socket.getInputStream());
            int length = in.readInt();
            if (length <= 0 || length > MAX_REPLY_LENGTH)
                return null;
            reply = new byte[length];
            in.readFully(reply);
        }
        catch (IOException e) {
            // Kerby's own request reports the KDC as unreachable
            return null;
        }

        KrbMessage answer;
        try {
            answer = KrbCodec.decodeMessage(ByteBuffer.wrap(reply));
        }
        catch (IOException e) {
            return null;
        }
        if (!(answer instanceof KrbError))
            return null;

        KrbError error = (KrbError) answer;
        if (error.getErrorCode() != KrbErrorCode.KDC_ERR_PREAUTH_REQUIRED || error.getEdata() == null)
            return null;

        for (PaDataEntry entry : KrbCodec.decode(error.getEdata(), MethodData.class).getElements()) {
            if (entry.getPaDataType() == PaDataType.ETYPE_INFO2 && entry.getPaDataValue() != null)
                return KrbCodec.decode(entry.getPaDataValue(), EtypeInfo2.class);
        }
        return null;

    }

    /**
     * A password request whose key follows the KDC's salt for the chosen
     * encryption type.
     */
    private static final class SaltAwareAsRequest extends AsRequestWithPasswd {

        private EtypeInfo2 advertised;

        private EncryptionType keyType;
        private EncryptionKey key;

        SaltAwareAsRequest(KrbContext context) {
            super(context);
        }

        @Override
        public EncryptionKey getClientKey() throws KrbException {

            EtypeInfo2Entry entry = advertisedEntry();
            if (entry == null || entry.getSalt() == null)
                return super.getClientKey();

            EncryptionType type = entry.getEtype();
            if (key == null || type != keyType) {
                key = new EncryptionKey(type, EncryptionHandler.getEncHandler(type)
                        .str2key(getPassword(), entry.getSalt(), entry.getS2kParams()));
                keyType = type;
            }

            setClientKey(key);
            return key;

        }

        /**
         * The KDC's entry for the chosen encryption type, or for its first
         * supported type if none is chosen yet.
         */
        private EtypeInfo2Entry advertisedEntry() {

            if (advertised == null)
                return null;

            EncryptionType chosen = getChosenEncryptionType();
            EtypeInfo2Entry first = null;
            for (EtypeInfo2Entry candidate : advertised.getElements()) {
                if (!EncryptionHandler.isImplemented(candidate.getEtype()))
                    continue;
                if (chosen == null || candidate.getEtype() == chosen)
                    return candidate;
                if (first == null)
                    first = candidate;
            }

            return chosen == null ? first : null;

        }

    }

}
