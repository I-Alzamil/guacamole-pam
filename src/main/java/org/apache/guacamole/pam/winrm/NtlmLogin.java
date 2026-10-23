package org.apache.guacamole.pam.winrm;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.EnumSet;
import java.util.Locale;
import java.util.Set;

import com.hierynomus.msdtyp.FileTime;
import com.hierynomus.ntlm.av.AvId;
import com.hierynomus.ntlm.av.AvPairChannelBindings;
import com.hierynomus.ntlm.av.AvPairTimestamp;
import com.hierynomus.ntlm.functions.NtlmV2Functions;
import com.hierynomus.ntlm.messages.NtlmAuthenticate;
import com.hierynomus.ntlm.messages.NtlmChallenge;
import com.hierynomus.ntlm.messages.NtlmNegotiate;
import com.hierynomus.ntlm.messages.NtlmNegotiateFlag;
import com.hierynomus.ntlm.messages.TargetInfo;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.commons.buffer.Endian;
import com.hierynomus.security.jce.JceSecurityProvider;

/**
 * NTLMv2 login to WinRM, sent in HTTP "Negotiate" headers. The messages and
 * responses come from smbj; this class only binds the login to the TLS
 * channel (extended protection, RFC 5929 "tls-server-end-point"), which
 * hosts with CbtHardeningLevel set to Strict require. TLS protects the
 * messages, so no signing or sealing is negotiated.
 */
final class NtlmLogin {

    private static final Set<NtlmNegotiateFlag> FLAGS = EnumSet.of(
            NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_UNICODE,
            NtlmNegotiateFlag.NTLMSSP_REQUEST_TARGET,
            NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_NTLM,
            NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_ALWAYS_SIGN,
            NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY,
            NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_128,
            NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_56);

    private static final String CHANNEL_BINDING_PREFIX = "tls-server-end-point:";

    private static final SecureRandom RANDOM = new SecureRandom();

    private final NtlmV2Functions functions = new NtlmV2Functions(RANDOM, new JceSecurityProvider());

    /**
     * The first message, announcing an NTLM login.
     */
    byte[] negotiate() {
        Buffer.PlainBuffer buffer = new Buffer.PlainBuffer(Endian.LE);
        new NtlmNegotiate(FLAGS, null, null, null, true).write(buffer);
        return buffer.getCompactData();
    }

    /**
     * The answer to the server's challenge, proving the password and naming
     * the TLS channel it is meant for.
     */
    byte[] authenticate(byte[] challengeMessage, WinRmTarget.Credentials user, String password,
            X509Certificate serverCertificate) throws Buffer.BufferException, GeneralSecurityException {

        NtlmChallenge challenge = new NtlmChallenge();
        challenge.read(new Buffer.PlainBuffer(challengeMessage, Endian.LE));

        TargetInfo targetInfo = challenge.getTargetInfo() == null ? new TargetInfo()
                : challenge.getTargetInfo().copy();
        targetInfo.putAvPair(new AvPairChannelBindings(channelBindingsHash(serverCertificate)));

        // The server's clock, if it sent it, avoids failures from clock skew
        boolean serverTime = targetInfo.hasAvPair(AvId.MsvAvTimestamp);
        long time = serverTime
                ? ((AvPairTimestamp) targetInfo.getAvPair(AvId.MsvAvTimestamp)).getValue().getWindowsTimeStamp()
                : FileTime.now().getWindowsTimeStamp();

        byte[] clientChallenge = new byte[8];
        RANDOM.nextBytes(clientChallenge);

        byte[] responseKey = functions.NTOWFv2(password, user.getName(), user.getDomain());
        byte[] ntResponse = functions.getNtV2Response(responseKey, challenge.getServerChallenge(),
                clientChallenge, time, targetInfo);

        // With the server's timestamp, the LMv2 response must be empty (zeros)
        byte[] lmResponse = serverTime ? new byte[24]
                : functions.getLmV2Response(responseKey, challenge.getServerChallenge(), clientChallenge);

        Buffer.PlainBuffer buffer = new Buffer.PlainBuffer(Endian.LE);
        new NtlmAuthenticate(lmResponse, ntResponse, user.getName(), user.getDomain(), null, null,
                FLAGS, null).write(buffer);
        return buffer.getCompactData();

    }

    /**
     * MD5 of the GSS channel bindings structure whose application data is
     * "tls-server-end-point:" followed by the certificate's hash: no
     * addresses, then the length and the data.
     */
    static byte[] channelBindingsHash(X509Certificate certificate) throws GeneralSecurityException {

        byte[] applicationData = concat(CHANNEL_BINDING_PREFIX.getBytes(StandardCharsets.US_ASCII),
                MessageDigest.getInstance(endPointHashAlgorithm(certificate)).digest(certificate.getEncoded()));

        ByteArrayOutputStream structure = new ByteArrayOutputStream();
        structure.write(new byte[16], 0, 16);
        int length = applicationData.length;
        structure.write(new byte[] {
            (byte) length, (byte) (length >>> 8), (byte) (length >>> 16), (byte) (length >>> 24)
        }, 0, 4);
        structure.write(applicationData, 0, length);

        return MessageDigest.getInstance("MD5").digest(structure.toByteArray());

    }

    /**
     * The certificate's signature hash, or SHA-256 instead of MD5 and SHA-1
     * (RFC 5929, section 4.1).
     */
    static String endPointHashAlgorithm(X509Certificate certificate) {
        String algorithm = certificate.getSigAlgName().toUpperCase(Locale.ROOT);
        if (algorithm.startsWith("SHA384"))
            return "SHA-384";
        if (algorithm.startsWith("SHA512"))
            return "SHA-512";
        return "SHA-256";
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }

}
