package org.apache.guacamole.pam.kerberos;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

import org.apache.guacamole.pam.rotation.ChangeOutcome;
import org.apache.kerby.KOptions;
import org.apache.kerby.kerberos.kerb.KrbCodec;
import org.apache.kerby.kerberos.kerb.KrbErrorCode;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.client.KrbClient;
import org.apache.kerby.kerberos.kerb.client.KrbConfig;
import org.apache.kerby.kerberos.kerb.client.KrbOption;
import org.apache.kerby.kerberos.kerb.crypto.EncryptionHandler;
import org.apache.kerby.kerberos.kerb.type.EncKrbPrivPart;
import org.apache.kerby.kerberos.kerb.type.KerberosTime;
import org.apache.kerby.kerberos.kerb.type.KrbPriv;
import org.apache.kerby.kerberos.kerb.type.ap.ApOptions;
import org.apache.kerby.kerberos.kerb.type.ap.ApRep;
import org.apache.kerby.kerberos.kerb.type.ap.ApReq;
import org.apache.kerby.kerberos.kerb.type.ap.Authenticator;
import org.apache.kerby.kerberos.kerb.type.ap.EncAPRepPart;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.type.base.HostAddress;
import org.apache.kerby.kerberos.kerb.type.base.KeyUsage;
import org.apache.kerby.kerberos.kerb.type.base.KrbError;
import org.apache.kerby.kerberos.kerb.type.base.NameType;
import org.apache.kerby.kerberos.kerb.type.base.PrincipalName;
import org.apache.kerby.kerberos.kerb.type.ticket.TgtTicket;

/**
 * Changes and verifies Kerberos passwords with the change and set password
 * protocol of RFC 3244 (kpasswd, port 464), served by MIT Kerberos, Heimdal
 * and Active Directory. A ticket for the password change service is obtained from the
 * KDC with the admin principal, which then sets the managed principal's
 * password, or with the managed principal itself, which changes its own.
 *
 * Kerberos authenticates both ends: the KDC proves it knows the password's
 * key, and the password change server answers with an AP-REP only it can
 * produce, so no certificate is involved.
 */
public class KerberosClient {

    private static final int TIMEOUT_MS = 15000;

    /**
     * Version of the original change password protocol, whose data is the
     * new password itself, for principals changing their own password.
     */
    private static final int CHANGE_PASSWORD_VERSION = 0x0001;

    /**
     * Version of the set password protocol, whose data also names the
     * principal, for admins setting another principal's password.
     */
    private static final int SET_PASSWORD_VERSION = 0xff80;

    private static final int MAX_REPLY_LENGTH = 64 * 1024;

    private static final String[] RESULT_CODES = {
        "success", "malformed request", "server error", "authentication error",
        "the password does not meet the password policy", "access denied", "bad protocol version",
        "an initial ticket is required"
    };

    private static final int RESULT_SOFT_ERROR = 4;

    private final SecureRandom random = new SecureRandom();

    /**
     * Changes the password of the target principal. Uses the admin principal
     * when configured, otherwise the principal changes its own password.
     * Never throws: every failure is reported in the outcome.
     */
    public ChangeOutcome changePassword(KerberosTarget target, String newPassword) {

        boolean useAdmin = target.getAdminPrincipal() != null;
        String client = useAdmin ? target.getAdminPrincipal() : target.getPrincipal();
        String clientPassword = useAdmin ? target.getAdminPassword() : target.getPassword();

        if (clientPassword == null)
            return new ChangeOutcome(false, false, "The account has no current password and no admin"
                    + " principal is configured.", null, null);

        TgtTicket ticket;
        try {
            KOptions options = new KOptions();
            options.add(KrbOption.USE_PASSWD, true);
            options.add(KrbOption.CLIENT_PRINCIPAL, client);
            options.add(KrbOption.USER_PASSWD, clientPassword);
            options.add(KrbOption.SERVER_PRINCIPAL, "kadmin/changepw@" + target.getRealm());
            ticket = newClient(target).requestTgt(options);
        }
        catch (KrbException e) {
            return new ChangeOutcome(false, false, describe(e, useAdmin), null, null);
        }

        boolean sent = false;
        try (Socket socket = new Socket()) {

            socket.connect(new InetSocketAddress(target.getKpasswdServer(), target.getKpasswdPort()), TIMEOUT_MS);
            socket.setSoTimeout(TIMEOUT_MS);

            EncryptionKey sessionKey = ticket.getSessionKey();
            EncryptionKey subkey = EncryptionHandler.random2Key(sessionKey.getKeyType());
            int sequence = random.nextInt() & 0x3fffffff;
            KerberosTime now = KerberosTime.now();
            int cusec = (int) (now.getTime() % 1000) * 1000;

            // AP-REQ authenticating with the ticket, carrying the subkey
            Authenticator authenticator = new Authenticator();
            authenticator.setAuthenticatorVno(5);
            authenticator.setCrealm(ticket.getClientPrincipal().getRealm());
            authenticator.setCname(ticket.getClientPrincipal());
            authenticator.setCtime(now);
            authenticator.setCusec(cusec);
            authenticator.setSubKey(subkey);
            authenticator.setSeqNumber(sequence);

            ApReq apReq = new ApReq();
            apReq.setApOptions(new ApOptions());
            apReq.setTicket(ticket.getTicket());
            apReq.setEncryptedAuthenticator(EncryptionHandler.encrypt(KrbCodec.encode(authenticator),
                    sessionKey, KeyUsage.AP_REQ_AUTH));

            // KRB-PRIV carrying the new password, with the target if set by an admin
            byte[] password = newPassword.getBytes(StandardCharsets.UTF_8);
            byte[] userData = password;
            if (useAdmin) {
                String principal = target.getPrincipal();
                int at = principal.lastIndexOf('@');
                ChangePasswdData data = new ChangePasswdData();
                data.setNewPassword(password);
                data.setTarget(new PrincipalName(principal.substring(0, at), NameType.NT_PRINCIPAL),
                        principal.substring(at + 1));
                userData = KrbCodec.encode(data);
            }

            EncKrbPrivPart privPart = new EncKrbPrivPart();
            privPart.setUserData(userData);
            privPart.setSeqNumber(sequence);
            privPart.setSAddress(new HostAddress(socket.getLocalAddress()));

            KrbPriv priv = new KrbPriv();
            priv.setEncryptedEncPart(EncryptionHandler.encrypt(KrbCodec.encode(privPart), subkey,
                    KeyUsage.KRB_PRIV_ENCPART));

            byte[] apReqBytes = KrbCodec.encode(apReq);
            byte[] privBytes = KrbCodec.encode(priv);
            int length = 6 + apReqBytes.length + privBytes.length;

            // Over TCP, the message is preceded by its length
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            out.writeInt(length);
            out.writeShort(length);
            out.writeShort(useAdmin ? SET_PASSWORD_VERSION : CHANGE_PASSWORD_VERSION);
            out.writeShort(apReqBytes.length);
            out.write(apReqBytes);
            out.write(privBytes);
            out.flush();
            sent = true;

            DataInputStream in = new DataInputStream(socket.getInputStream());
            int replyLength = in.readInt();
            if (replyLength <= 0 || replyLength > MAX_REPLY_LENGTH)
                throw new IOException("Invalid reply length " + replyLength + ".");
            byte[] reply = new byte[replyLength];
            in.readFully(reply);

            return readReply(reply, sessionKey, subkey, now, cusec);

        }
        catch (KrbException | IOException | RuntimeException e) {
            return new ChangeOutcome(false, sent, (sent ? "No valid answer from the password change server"
                    : "Unable to reach the password change server ") + target.getKpasswdServer() + ":"
                    + target.getKpasswdPort() + ": " + message(e), null, null);
        }

    }

    /**
     * Returns whether the KDC accepts the given password for the target
     * principal, by asking for a ticket with it.
     *
     * @throws KrbException
     *     If the KDC could not be reached or refused for another reason.
     */
    public boolean acceptsPassword(KerberosTarget target, String password) throws KrbException {

        if (password == null || password.isEmpty())
            return false;

        try {
            newClient(target).requestTgt(target.getPrincipal(), password);
            return true;
        }
        catch (KrbException e) {
            if (isWrongPassword(e))
                return false;
            throw e;
        }

    }

    private static KrbClient newClient(KerberosTarget target) throws KrbException {
        KrbClient client = new KrbClient(new KrbConfig());
        client.setKdcRealm(target.getRealm());
        client.setKdcHost(target.getKdc());
        client.setKdcTcpPort(target.getKdcPort());
        client.setAllowTcp(true);
        client.setAllowUdp(false);
        client.setTimeout(TIMEOUT_MS);
        client.init();
        return client;
    }

    /**
     * Reads the reply: an AP-REP proving the server's identity followed by a
     * KRB-PRIV holding the result, or a KRB-ERROR.
     */
    private ChangeOutcome readReply(byte[] reply, EncryptionKey sessionKey, EncryptionKey subkey,
            KerberosTime ctime, int cusec) throws KrbException, IOException {

        ByteBuffer buffer = ByteBuffer.wrap(reply);

        // Some servers answer a request they cannot parse with a bare KRB-ERROR
        if ((reply[0] & 0xff) == 0x7e)
            return refused(KrbCodec.decode(reply, KrbError.class));

        if (reply.length < 6)
            throw new IOException("Reply too short.");

        buffer.getShort(); // Length
        buffer.getShort(); // Version
        int apRepLength = buffer.getShort() & 0xffff;
        byte[] rest = new byte[buffer.remaining() - apRepLength];

        if (apRepLength == 0) {
            buffer.get(rest);
            return refused(KrbCodec.decode(rest, KrbError.class));
        }

        byte[] apRepBytes = new byte[apRepLength];
        buffer.get(apRepBytes);
        buffer.get(rest);

        // Mutual authentication: only the service can echo our time
        ApRep apRep = KrbCodec.decode(apRepBytes, ApRep.class);
        EncAPRepPart repPart = KrbCodec.decode(EncryptionHandler.decrypt(apRep.getEncryptedEncPart(),
                sessionKey, KeyUsage.AP_REP_ENCPART), EncAPRepPart.class);
        if (repPart.getCtime() == null || repPart.getCtime().getTimeInSeconds() != ctime.getTimeInSeconds()
                || repPart.getCusec() != cusec)
            throw new IOException("The password change server failed mutual authentication.");

        KrbPriv priv = KrbCodec.decode(rest, KrbPriv.class);
        EncKrbPrivPart privPart = decryptPriv(priv, repPart.getSubkey(), subkey);

        byte[] userData = privPart.getUserData();
        if (userData == null || userData.length < 2)
            throw new IOException("Empty result.");

        int code = ((userData[0] & 0xff) << 8) | (userData[1] & 0xff);
        if (code == 0)
            return new ChangeOutcome(true, true, null, null, null);

        return new ChangeOutcome(false, true, "The password change server refused: "
                + describeResult(code, userData), null, null);

    }

    /**
     * Decrypts the result with the server's subkey from the AP-REP if it
     * sent one, otherwise (or if that fails) with ours.
     */
    private static EncKrbPrivPart decryptPriv(KrbPriv priv, EncryptionKey serverSubkey, EncryptionKey subkey)
            throws KrbException {
        if (serverSubkey != null) {
            try {
                return KrbCodec.decode(EncryptionHandler.decrypt(priv.getEncryptedEncPart(), serverSubkey,
                        KeyUsage.KRB_PRIV_ENCPART), EncKrbPrivPart.class);
            }
            catch (KrbException e) {
                // Fall back on the client subkey
            }
        }
        return KrbCodec.decode(EncryptionHandler.decrypt(priv.getEncryptedEncPart(), subkey,
                KeyUsage.KRB_PRIV_ENCPART), EncKrbPrivPart.class);
    }

    /**
     * A KRB-ERROR answering the request. The password change result, if
     * any, is in its e-data. The new password may have been read, so it
     * counts as sent.
     */
    private static ChangeOutcome refused(KrbError error) {
        byte[] data = error.getEdata();
        String detail = data != null && data.length >= 2
                ? describeResult(((data[0] & 0xff) << 8) | (data[1] & 0xff), data)
                : error.getErrorCode() + (error.getEtext() == null ? "" : " (" + error.getEtext() + ")");
        return new ChangeOutcome(false, true, "The password change server refused: " + detail, null, null);
    }

    /**
     * The result code with the server's explanation. Active Directory sends
     * its password policy as binary data instead of text, which is left out.
     */
    private static String describeResult(int code, byte[] data) {

        String name = code >= 0 && code < RESULT_CODES.length ? RESULT_CODES[code] : "result " + code;

        String text = "";
        if (data.length > 2) {
            boolean adPolicy = code == RESULT_SOFT_ERROR && data.length == 32 && data[2] == 0 && data[3] == 0;
            if (!adPolicy)
                text = new String(data, 2, data.length - 2, StandardCharsets.UTF_8).trim();
        }

        return text.isEmpty() ? name : name + " (" + text + ")";

    }

    private static boolean isWrongPassword(KrbException e) {
        KrbErrorCode code = e.getKrbErrorCode();
        return code == KrbErrorCode.KDC_ERR_PREAUTH_FAILED || code == KrbErrorCode.KRB_AP_ERR_BAD_INTEGRITY;
    }

    private static String describe(KrbException e, boolean useAdmin) {
        KrbErrorCode code = e.getKrbErrorCode();
        if (isWrongPassword(e))
            return useAdmin ? "The KDC rejected the admin principal's password."
                            : "The KDC rejected the account's current password.";
        if (code == KrbErrorCode.KDC_ERR_C_PRINCIPAL_UNKNOWN)
            return useAdmin ? "The KDC does not know the admin principal."
                            : "The KDC does not know the account's principal.";
        if (code == KrbErrorCode.KDC_ERR_S_PRINCIPAL_UNKNOWN)
            return "The realm has no password change service (kadmin/changepw).";
        return "Unable to get a password change ticket from the KDC: " + message(e);
    }

    private static String message(Throwable error) {
        Throwable root = error;
        while (root.getCause() != null && root.getCause() != root)
            root = root.getCause();
        String text = error.getMessage() != null ? error.getMessage() : root.getMessage();
        return text == null ? error.getClass().getSimpleName() : text;
    }

}
