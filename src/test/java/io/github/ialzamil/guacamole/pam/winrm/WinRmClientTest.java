package io.github.ialzamil.guacamole.pam.winrm;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.HashMap;
import java.util.Map;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import io.github.ialzamil.guacamole.pam.rotation.ChangeOutcome;

/**
 * The WinRM client against a fake Windows endpoint: the remote shell
 * lifecycle, values passed on stdin only, certificate pinning, and how
 * Windows' answers are reported.
 */
public class WinRmClientTest {

    /**
     * SHA-256 fingerprint of the fake endpoint's certificate.
     */
    private static final String FINGERPRINT =
            "B8:9F:D6:DE:0D:72:5C:59:6D:66:25:97:96:32:58:C8:E5:2F:93:C3:BB:4A:EF:EC:3B:D2:EA:5C:3E:BE:F4:53";

    private static final String OTHER_FINGERPRINT =
            "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99";

    private FakeWinRmServer windows;
    private final WinRmClient client = new WinRmClient();

    @Before
    public void start() throws Exception {
        windows = new FakeWinRmServer();
    }

    @After
    public void stop() throws Exception {
        windows.close();
    }

    private WinRmTarget target(boolean admin, String certificate) {
        return target(admin, certificate, null);
    }

    private WinRmTarget target(boolean admin, String certificate, String authorities) {
        Map<String, String> values = new HashMap<>();
        if (authorities != null)
            values.put(WinRmTarget.CA_CERTIFICATES, authorities);
        values.put(WinRmTarget.HOSTNAME, "localhost");
        values.put(WinRmTarget.PORT, Integer.toString(windows.getPort()));
        values.put(WinRmTarget.USERNAME, "pamtest");
        values.put(WinRmTarget.PASSWORD, "Current-Pw1!");
        if (certificate != null)
            values.put(WinRmTarget.CERTIFICATE, certificate);
        if (admin) {
            values.put(WinRmTarget.ADMIN_USERNAME, "Administrator");
            values.put(WinRmTarget.ADMIN_PASSWORD, "Admin-Pw1!");
        }
        return WinRmTarget.fromParameters(values);
    }

    @Test
    public void adminSetsThePasswordGivenOnStdinOnly() {

        ChangeOutcome outcome = client.changePassword(target(true, FINGERPRINT), "New-Pw1!");

        assertTrue(outcome.getError(), outcome.isCompleted());
        assertTrue(outcome.isNewPasswordSent());
        assertEquals(FINGERPRINT, outcome.getHostKey());

        assertEquals("pamtest\nNew-Pw1!\n", windows.stdin.toString());
        String commandLine = String.join(" ", windows.commandLines);
        assertFalse(commandLine.contains("New-Pw1!"));
        assertFalse(commandLine.contains("Admin-Pw1!"));
        assertFalse(commandLine.contains("pamtest"));

        // Logged in (two NTLM messages), waited out a timeout, and cleaned up
        assertEquals(2, windows.ntlmMessages);
        assertEquals("[Create, Command, Send, Receive, Receive, Signal, Delete]", windows.actions.toString());

    }

    @Test
    public void accountSetsItsOwnPassword() {
        ChangeOutcome outcome = client.changePassword(target(false, FINGERPRINT), "New-Pw1!");
        assertTrue(outcome.getError(), outcome.isCompleted());
        assertEquals("New-Pw1!\n", windows.stdin.toString());
    }

    @Test
    public void wrongCertificateGetsNoRequestAtAll() {
        ChangeOutcome outcome = client.changePassword(target(true, OTHER_FINGERPRINT), "New-Pw1!");
        assertFalse(outcome.isCompleted());
        assertFalse(outcome.isNewPasswordSent());
        assertTrue(outcome.getError(), outcome.getError().contains("does not match the trusted fingerprint"));
        assertTrue(outcome.getError(), outcome.getError().contains("No credentials were sent"));
        assertEquals(0, windows.requests);
    }

    @Test
    public void firstContactRecordsTheCertificate() {
        ChangeOutcome outcome = client.changePassword(target(true, null), "New-Pw1!");
        assertTrue(outcome.getError(), outcome.isCompleted());
        assertEquals(FINGERPRINT, outcome.getHostKey());
    }

    @Test
    public void refusedLoginChangesNothing() {
        windows.refuseLogin = true;
        ChangeOutcome outcome = client.changePassword(target(true, FINGERPRINT), "New-Pw1!");
        assertFalse(outcome.isNewPasswordSent());
        assertEquals("The host refused the administrator's credentials.", outcome.getError());
        assertEquals("", windows.stdin.toString());

        outcome = client.changePassword(target(false, FINGERPRINT), "New-Pw1!");
        assertEquals("The host refused the account's current password.", outcome.getError());
    }

    @Test
    public void reportsWhatWindowsRefused() {
        windows.stdout = "";
        windows.exitCode = 1;
        windows.stderr = "#< CLIXML\r\n<Objs Version=\"1.1.0.1\" xmlns=\"http://schemas.microsoft.com/powershell/2004/04\">"
                + "<S S=\"Error\">Exception calling \"SetPassword\" with \"1\" argument(s): \"The password does not meet"
                + " the password policy requirements.\"_x000D__x000A_</S></Objs>";

        ChangeOutcome outcome = client.changePassword(target(true, FINGERPRINT), "short");
        assertFalse(outcome.isCompleted());
        assertTrue(outcome.isNewPasswordSent());
        assertTrue(outcome.getError(), outcome.getError().startsWith("Windows refused the password change:"));
        assertTrue(outcome.getError(), outcome.getError().contains("does not meet the password policy"));
    }

    @Test
    public void adminChecksPasswordsOnTheHost() throws Exception {
        windows.stdout = "PAM-VALID\r\n";
        WinRmClient.Check check = client.acceptsPassword(target(true, FINGERPRINT), "Some-Pw1!");
        assertTrue(check.isAccepted());
        assertEquals(FINGERPRINT, check.getCertificate());
        assertEquals("pamtest\nSome-Pw1!\n", windows.stdin.toString());
        assertFalse(String.join(" ", windows.commandLines).contains("Some-Pw1!"));
    }

    @Test
    public void adminCheckReportsWrongPasswords() throws Exception {
        windows.stdout = "PAM-INVALID\r\n";
        assertFalse(client.acceptsPassword(target(true, FINGERPRINT), "Wrong-Pw1!").isAccepted());
    }

    @Test
    public void accountCheckIsItsLogin() throws Exception {
        assertTrue(client.acceptsPassword(target(false, FINGERPRINT), "Some-Pw1!").isAccepted());
        windows.refuseLogin = true;
        assertFalse(client.acceptsPassword(target(false, FINGERPRINT), "Wrong-Pw1!").isAccepted());
    }

    // ---- Certificate authorities ----

    /**
     * SHA-256 fingerprint of the certificate test-ca.pem issued for
     * "localhost".
     */
    private static final String CA_ISSUED_FINGERPRINT =
            "18:2F:6A:F1:AD:A4:E5:E3:C5:A5:C8:B0:34:B4:FB:1A:CB:E1:9C:5B:37:8C:B7:96:83:A4:EA:27:C9:91:3F:CE";

    private static String pem(String resource) throws Exception {
        try (java.io.InputStream in = WinRmClientTest.class.getResourceAsStream(resource)) {
            return new String(in.readAllBytes(), java.nio.charset.StandardCharsets.US_ASCII);
        }
    }

    /**
     * Restarts the fake endpoint with the certificate of the given key store.
     */
    private void presenting(String keyStore) throws Exception {
        windows.close();
        windows = new FakeWinRmServer(keyStore);
    }

    @Test
    public void trustsACertificateIssuedByTheCa() throws Exception {
        presenting("test-ca-server.p12");
        ChangeOutcome outcome = client.changePassword(target(true, null, pem("test-ca.pem")), "New-Pw1!");
        assertTrue(outcome.getError(), outcome.isCompleted());
        assertEquals(CA_ISSUED_FINGERPRINT, outcome.getHostKey());
    }

    @Test
    public void trustsAnyOfSeveralCas() throws Exception {
        presenting("test-ca-server.p12");
        ChangeOutcome outcome = client.changePassword(
                target(true, null, pem("test-other-ca.pem") + pem("test-ca.pem")), "New-Pw1!");
        assertTrue(outcome.getError(), outcome.isCompleted());
    }

    @Test
    public void refusesACertificateOfAnotherCa() throws Exception {
        presenting("test-ca-server.p12");
        assertRefusedBeforeAnyRequest(client.changePassword(target(true, null, pem("test-other-ca.pem")), "New-Pw1!"));
    }

    @Test
    public void refusesASelfSignedCertificateOnceCasAreTrusted() throws Exception {
        // The certificate a first contact would have accepted
        assertRefusedBeforeAnyRequest(client.changePassword(target(true, null, pem("test-ca.pem")), "New-Pw1!"));
    }

    @Test
    public void refusesACertificateOfTheCaForAnotherName() throws Exception {
        presenting("test-ca-wrong-name.p12");
        ChangeOutcome outcome = client.changePassword(target(true, null, pem("test-ca.pem")), "New-Pw1!");
        assertRefusedBeforeAnyRequest(outcome);
        assertTrue(outcome.getError(), outcome.getError().contains("localhost"));
    }

    @Test
    public void aPinnedFingerprintWinsOverTheCas() throws Exception {
        presenting("test-ca-server.p12");
        ChangeOutcome outcome = client.changePassword(
                target(true, CA_ISSUED_FINGERPRINT, pem("test-other-ca.pem")), "New-Pw1!");
        assertTrue(outcome.getError(), outcome.isCompleted());
        windows.requests = 0;
        assertRefusedBeforeAnyRequest(client.changePassword(
                target(true, OTHER_FINGERPRINT, pem("test-ca.pem")), "New-Pw1!"));
    }

    private void assertRefusedBeforeAnyRequest(ChangeOutcome outcome) {
        assertFalse(outcome.isCompleted());
        assertFalse(outcome.isNewPasswordSent());
        assertTrue(outcome.getError(), outcome.getError().contains("No credentials were sent"));
        assertEquals(0, windows.requests);
    }

}
