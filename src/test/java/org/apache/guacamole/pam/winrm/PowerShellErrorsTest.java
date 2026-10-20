package org.apache.guacamole.pam.winrm;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

/**
 * PowerShell's CLIXML stderr, as WinRM returns it, read as plain text.
 */
public class PowerShellErrorsTest {

    /**
     * Recorded from Windows 11 (ADSI ChangePassword refused over WinRM).
     */
    private static final String RECORDED = "#< CLIXML\r\n<Objs Version=\"1.1.0.1\""
        + " xmlns=\"http://schemas.microsoft.com/powershell/2004/04\"><S S=\"Error\">Exception calling"
        + " \"ChangePassword\" with \"2\" argument(s): \"Access is denied.\"_x000D__x000A_</S>"
        + "<S S=\"Error\">At line:1 char:96_x000D__x000A_</S>"
        + "<S S=\"Error\">+ CategoryInfo          : NotSpecified: (:) [], ParentContainsErrorRecordException"
        + "_x000D__x000A_</S></Objs>";

    @Test
    public void readsErrorStreamsAsText() {
        assertEquals("Exception calling \"ChangePassword\" with \"2\" argument(s): \"Access is denied.\""
                + " At line:1 char:96 + CategoryInfo : NotSpecified: (:) [], ParentContainsErrorRecordException",
                WsMan.powerShellErrors(RECORDED));
    }

    /**
     * Escaped characters are decoded; whitespace, including the decoded
     * tab, becomes single spaces, so an error reads as one line.
     */
    @Test
    public void decodesEscapesAndEntities() {
        assertEquals("a < b & \"c\" done",
                WsMan.powerShellErrors("#< CLIXML <Objs><S S=\"Error\">a &lt; b &amp; \"c\"_x0009_done</S></Objs>"));
    }

    /**
     * Progress records carry no error and give no text.
     */
    @Test
    public void ignoresProgressOnlyOutput() {
        assertEquals("", WsMan.powerShellErrors("#< CLIXML\r\n<Objs Version=\"1.1.0.1\"><Obj S=\"progress\""
                + " RefId=\"0\"><TN RefId=\"0\"><T>System.Management.Automation.PSCustomObject</T></TN></Obj></Objs>"));
    }

    @Test
    public void keepsPlainTextAsIs() {
        assertEquals("plain failure", WsMan.powerShellErrors("  plain failure \n"));
    }

}
