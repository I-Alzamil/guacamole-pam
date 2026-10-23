package io.github.ialzamil.guacamole.pam.winrm;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

/**
 * The WS-Management messages of a remote shell (MS-WSMV): building the SOAP
 * envelopes, and reading the replies, their faults and PowerShell's errors.
 */
final class WsMan {

    static final String NS_SOAP = "http://www.w3.org/2003/05/soap-envelope";
    static final String NS_SHELL = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell";
    static final String NS_FAULT = "http://schemas.microsoft.com/wbem/wsman/1/wsmanfault";

    static final String ACTION_CREATE = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create";
    static final String ACTION_DELETE = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete";

    /**
     * Prefix of the shell's resource and of its actions (Command, Send,
     * Receive, Signal).
     */
    static final String SHELL = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/";

    /**
     * Fault code of a Receive with no output within the operation timeout.
     */
    private static final String TIMEOUT_FAULT_CODE = "2150858793";

    /**
     * Error PowerShell writes, in its CLIXML form, to stderr.
     */
    private static final Pattern CLIXML_ERROR = Pattern.compile("<S S=\"Error\">(.*?)</S>", Pattern.DOTALL);
    private static final Pattern CLIXML_ESCAPE = Pattern.compile("_x([0-9A-Fa-f]{4})_");

    private WsMan() {
    }

    /**
     * An envelope for the cmd shell resource.
     *
     * @param to
     *     The endpoint, such as "https://host:5986/wsman".
     *
     * @param shellId
     *     The shell the action applies to, or null.
     *
     * @param options
     *     Options made by {@link #option}, or null.
     */
    static String envelope(String to, String action, String shellId, String options, String body) {
        return "<s:Envelope xmlns:s=\"" + NS_SOAP + "\""
            + " xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\""
            + " xmlns:w=\"http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd\" xmlns:rsp=\"" + NS_SHELL + "\">"
            + "<s:Header>"
            + "<a:To>" + escape(to) + "</a:To>"
            + "<w:ResourceURI s:mustUnderstand=\"true\">" + SHELL + "cmd</w:ResourceURI>"
            + "<a:ReplyTo><a:Address s:mustUnderstand=\"true\">"
            + "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo>"
            + "<a:Action s:mustUnderstand=\"true\">" + action + "</a:Action>"
            + "<w:MaxEnvelopeSize s:mustUnderstand=\"true\">153600</w:MaxEnvelopeSize>"
            + "<a:MessageID>uuid:" + UUID.randomUUID() + "</a:MessageID>"
            + "<w:Locale xml:lang=\"en-US\" s:mustUnderstand=\"false\"/>"
            + "<w:OperationTimeout>PT20S</w:OperationTimeout>"
            + (shellId == null ? "" : "<w:SelectorSet><w:Selector Name=\"ShellId\">" + escape(shellId)
                    + "</w:Selector></w:SelectorSet>")
            + (options == null ? "" : "<w:OptionSet>" + options + "</w:OptionSet>")
            + "</s:Header><s:Body>" + body + "</s:Body></s:Envelope>";
    }

    static String option(String name, String value) {
        return "<w:Option Name=\"" + name + "\">" + value + "</w:Option>";
    }

    /**
     * Parses a reply, refusing document type declarations (and so external
     * entities).
     */
    static Document parse(byte[] xml) throws IOException {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setExpandEntityReferences(false);
            return factory.newDocumentBuilder().parse(new ByteArrayInputStream(xml));
        }
        catch (ParserConfigurationException | SAXException e) {
            throw new IOException("Invalid WinRM response: " + e.getMessage(), e);
        }
    }

    /**
     * The text of the first element of the shell namespace with this name,
     * or null.
     */
    static String text(Document document, String name) {
        NodeList nodes = document.getElementsByTagNameNS(NS_SHELL, name);
        return nodes.getLength() == 0 ? null : nodes.item(0).getTextContent().trim();
    }

    /**
     * Whether the reply only says that no output came within the operation
     * timeout.
     */
    static boolean isTimeoutFault(byte[] body) {
        try {
            NodeList faults = parse(body).getElementsByTagNameNS(NS_FAULT, "WSManFault");
            return faults.getLength() > 0
                    && TIMEOUT_FAULT_CODE.equals(((Element) faults.item(0)).getAttribute("Code"));
        }
        catch (IOException e) {
            return false;
        }
    }

    /**
     * The message of a fault, or the start of the body if it has none.
     */
    static String fault(byte[] body) {
        try {
            Document document = parse(body);
            NodeList messages = document.getElementsByTagNameNS(NS_FAULT, "Message");
            if (messages.getLength() > 0)
                return messages.item(0).getTextContent().trim();
            NodeList texts = document.getElementsByTagNameNS(NS_SOAP, "Text");
            if (texts.getLength() > 0)
                return texts.item(0).getTextContent().trim();
        }
        catch (IOException e) {
            // Not XML
        }
        String text = new String(body, StandardCharsets.UTF_8).trim();
        return text.isEmpty() ? "no details" : text.substring(0, Math.min(text.length(), 300));
    }

    /**
     * The error messages in PowerShell's CLIXML stderr, as plain text.
     */
    static String powerShellErrors(String stderr) {
        StringBuilder errors = new StringBuilder();
        Matcher matcher = CLIXML_ERROR.matcher(stderr);
        while (matcher.find()) {
            Matcher escape = CLIXML_ESCAPE.matcher(matcher.group(1));
            StringBuffer text = new StringBuffer();
            while (escape.find())
                escape.appendReplacement(text, Matcher.quoteReplacement(
                        String.valueOf((char) Integer.parseInt(escape.group(1), 16))));
            escape.appendTail(text);
            errors.append(text.toString().replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&"));
        }
        String result = errors.toString().replaceAll("\\s+", " ").trim();
        return result.isEmpty() ? (stderr.contains("CLIXML") ? "" : stderr.trim()) : result;
    }

    static String escape(String value) {
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }

}
