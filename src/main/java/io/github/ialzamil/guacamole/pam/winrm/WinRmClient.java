package io.github.ialzamil.guacamole.pam.winrm;

import java.io.IOException;

import io.github.ialzamil.guacamole.pam.rotation.ChangeOutcome;

/**
 * Sets and verifies passwords of local Windows accounts over WinRM, with
 * fixed PowerShell scripts that read every value from stdin. With an
 * administrator configured, it sets the account's password and checks
 * passwords on the host; otherwise the account (an administrator itself)
 * logs in with its current password and sets its own.
 */
public class WinRmClient {

    private static final String OK = "PAM-OK";
    private static final String VALID = "PAM-VALID";
    private static final String INVALID = "PAM-INVALID";

    /**
     * Reads the account name and its new password.
     */
    private static final String SET_PASSWORD_SCRIPT =
          "$ErrorActionPreference = 'Stop'\n"
        + "$name = [Console]::In.ReadLine()\n"
        + "$password = [Console]::In.ReadLine()\n"
        + "([ADSI]('WinNT://./' + $name + ',user')).SetPassword($password)\n"
        + "'" + OK + "'\n";

    /**
     * Reads the new password of the logged in account. Windows refuses a
     * change with the old password over WinRM, so the account (an
     * administrator) sets it; its login already proved the old one.
     */
    private static final String SET_OWN_PASSWORD_SCRIPT =
          "$ErrorActionPreference = 'Stop'\n"
        + "$password = [Console]::In.ReadLine()\n"
        + "([ADSI]('WinNT://./' + $env:USERNAME + ',user')).SetPassword($password)\n"
        + "'" + OK + "'\n";

    /**
     * Reads an account name and a password, and checks them on the host. A
     * domain controller has no accounts of its own (its "local" accounts are
     * the domain's), so there they are checked against the domain.
     */
    private static final String CHECK_PASSWORD_SCRIPT =
          "$ErrorActionPreference = 'Stop'\n"
        + "$name = [Console]::In.ReadLine()\n"
        + "$password = [Console]::In.ReadLine()\n"
        + "Add-Type -AssemblyName System.DirectoryServices.AccountManagement\n"
        + "$type = if ((Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4) { 'Domain' } else { 'Machine' }\n"
        + "$context = New-Object System.DirectoryServices.AccountManagement.PrincipalContext("
        + "[System.DirectoryServices.AccountManagement.ContextType]::$type)\n"
        + "try { if ($context.ValidateCredentials($name, $password)) { '" + VALID + "' }"
        + " else { '" + INVALID + "' } } finally { $context.Dispose() }\n";

    /**
     * Whether a password was accepted, with the certificate the host
     * presented while checking.
     */
    public static final class Check {

        private final boolean accepted;
        private final String certificate;

        Check(boolean accepted, String certificate) {
            this.accepted = accepted;
            this.certificate = certificate;
        }

        public boolean isAccepted() {
            return accepted;
        }

        public String getCertificate() {
            return certificate;
        }

    }

    /**
     * Sets the account's new password. Never throws: every failure is
     * reported in the outcome, with the host's certificate if seen.
     */
    public ChangeOutcome changePassword(WinRmTarget target, String newPassword) {

        boolean useAdmin = target.getAdmin() != null;
        if (!useAdmin && target.getPassword() == null)
            return new ChangeOutcome(false, false, "The account has no current password and no administrator"
                    + " is configured.", null, null);

        WinRmSession session = useAdmin
                ? new WinRmSession(target, target.getAdmin(), target.getAdminPassword())
                : new WinRmSession(target, target.getAccount(), target.getPassword());

        try {

            session.connect();
            WinRmSession.Result result = useAdmin
                    ? session.runPowerShell(SET_PASSWORD_SCRIPT, target.getAccount().getName() + "\n" + newPassword + "\n")
                    : session.runPowerShell(SET_OWN_PASSWORD_SCRIPT, newPassword + "\n");

            if (result.getExitCode() != 0 || !result.getOutput().contains(OK))
                return new ChangeOutcome(false, true, "Windows refused the password change: "
                        + describe(result), null, session.getPresentedCertificate());

            return new ChangeOutcome(true, true, null, null, session.getPresentedCertificate());

        }
        // Windows refuses accounts that may not use WinRM as it refuses wrong
        // passwords
        catch (WinRmSession.LoginRefusedException e) {
            return new ChangeOutcome(false, false, useAdmin
                    ? "The host refused the administrator's credentials."
                    : "The host refused the account's sign-in: its current password is wrong, or it may not use"
                        + " WinRM, which Windows allows administrators only. Configure an administrator on the"
                        + " platform to change the passwords of other accounts.", null,
                    session.getPresentedCertificate());
        }
        catch (IOException | RuntimeException e) {
            // Once given its input, the script may have run with the new password
            String error = describe(target, e);
            if (!useAdmin && !session.isInputSent() && error.contains("Access is denied"))
                error += " The account may not use WinRM's remote shell, which Windows allows administrators only"
                        + " (unless its RootSDDL grants more): configure an administrator on the platform instead.";
            return new ChangeOutcome(false, session.isInputSent(), error, null, session.getPresentedCertificate());
        }
        finally {
            session.close();
        }

    }

    /**
     * Returns whether the host accepts the given password for the account:
     * checked on the host by the administrator, or else by logging in as
     * the account.
     *
     * @throws IOException
     *     If the host could not be reached, is not trusted, or refused the
     *     administrator.
     */
    public Check acceptsPassword(WinRmTarget target, String password) throws IOException {

        if (password == null || password.isEmpty())
            return new Check(false, null);

        if (target.getAdmin() == null) {
            try (WinRmSession session = new WinRmSession(target, target.getAccount(), password)) {
                session.connect();
                try {
                    session.runPowerShell("'" + OK + "'", "");
                    return new Check(true, session.getPresentedCertificate());
                }
                catch (WinRmSession.LoginRefusedException e) {
                    return new Check(false, session.getPresentedCertificate());
                }
            }
        }

        try (WinRmSession session = new WinRmSession(target, target.getAdmin(), target.getAdminPassword())) {
            session.connect();
            WinRmSession.Result result;
            try {
                result = session.runPowerShell(CHECK_PASSWORD_SCRIPT,
                        target.getAccount().getName() + "\n" + password + "\n");
            }
            catch (WinRmSession.LoginRefusedException e) {
                throw new IOException("The host refused the administrator's credentials.", e);
            }
            if (result.getOutput().contains(VALID))
                return new Check(true, session.getPresentedCertificate());
            if (result.getOutput().contains(INVALID))
                return new Check(false, session.getPresentedCertificate());
            throw new IOException("Unable to check the password on the host: " + describe(result));
        }

    }

    private static String describe(WinRmSession.Result result) {
        String error = result.getError();
        return error == null || error.isEmpty() ? "PowerShell exited with code " + result.getExitCode() + "."
                : error;
    }

    private static String describe(WinRmTarget target, Exception e) {
        String message = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
        if (e instanceof java.net.ConnectException || e instanceof java.net.SocketTimeoutException
                || e instanceof java.net.UnknownHostException)
            return "Unable to reach WinRM on " + target.getHostname() + ":" + target.getPort() + " (" + message
                    + "). WinRM must listen on HTTPS.";
        Throwable cause = e;
        while (cause.getCause() != null && cause.getCause() != cause)
            cause = cause.getCause();
        if (cause instanceof java.security.cert.CertificateException)
            return cause.getMessage();
        return message;
    }

}
