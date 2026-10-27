package io.github.ialzamil.guacamole.pam.rest;

import java.time.DateTimeException;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;

import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import org.apache.guacamole.GuacamoleClientException;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleResourceNotFoundException;
import org.apache.guacamole.net.auth.AuthenticatedUser;

import io.github.ialzamil.guacamole.pam.PamAuthenticationProvider;
import io.github.ialzamil.guacamole.pam.notification.email.EmailLanguage;
import io.github.ialzamil.guacamole.pam.notification.email.EmailLanguages;
import io.github.ialzamil.guacamole.pam.notification.email.EmailSettings;

/**
 * The languages of emails, at "email-languages", for the Email Templates
 * tab: administrators only. Each is read and written as its file is
 * exported and imported (see {@link EmailLanguage}).
 */
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class EmailLanguagesResource extends PamResource {

    EmailLanguagesResource(PamAuthenticationProvider provider, AuthenticatedUser user) {
        super(provider, user);
    }

    /**
     * Every language, English first, with how many users chose each.
     */
    @GET
    public List<EmailLanguages.Summary> list() throws GuacamoleException {
        requireAdministrator();
        return provider.getEmailLanguages().list();
    }

    /**
     * English as built into the extension, to translate from.
     */
    @GET
    @Path("built-in")
    public EmailLanguage getBuiltIn() throws GuacamoleException {
        requireAdministrator();
        return EmailLanguages.getBuiltIn();
    }

    /**
     * A language as in effect, complete: what it leaves out is English.
     */
    @GET
    @Path("{code}")
    public EmailLanguage get(@PathParam("code") String code) throws GuacamoleException {
        requireAdministrator();
        EmailLanguage language = provider.getEmailLanguages().get(code);
        if (language == null)
            throw new GuacamoleResourceNotFoundException("No such email language.");
        return language;
    }

    /**
     * Adds or replaces the language of the code given, as given. Returns it
     * as then in effect.
     */
    @PUT
    @Path("{code}")
    public EmailLanguage save(@PathParam("code") String code, EmailLanguage language) throws GuacamoleException {
        requireAdministrator();
        if (language == null || !code.equals(language.getCode()))
            throw new GuacamoleClientException("The code of the language is not that of its address.");
        return provider.getEmailLanguages().save(language, username());
    }

    /**
     * Deletes an added language; for English, restores what is built in.
     */
    @DELETE
    @Path("{code}")
    public void delete(@PathParam("code") String code) throws GuacamoleException {
        requireAdministrator();
        provider.getEmailLanguages().delete(code, username());
    }

    /**
     * The subject and text ("subject", "body") of a kind of email ("kind")
     * in a language as given ("language"), unsaved, for a sample event, with
     * Guacamole's address and the time zone of the email settings.
     */
    @POST
    @Path("preview")
    public Map<String, String> preview(Preview preview) throws GuacamoleException {
        requireAdministrator();
        if (preview == null)
            throw new GuacamoleClientException("Nothing to preview.");
        ZoneId zone;
        try {
            zone = ZoneId.of((String) provider.getSettings().get(EmailSettings.TIME_ZONE));
        }
        catch (DateTimeException e) {
            zone = ZoneOffset.UTC;
        }
        return provider.getEmailLanguages().preview(preview.getLanguage(), preview.getKind(),
                (String) provider.getSettings().get(EmailSettings.LINK), zone);
    }

    /**
     * What to preview.
     */
    public static final class Preview {

        private EmailLanguage language;
        private String kind;

        public EmailLanguage getLanguage() {
            return language;
        }

        public void setLanguage(EmailLanguage language) {
            this.language = language;
        }

        public String getKind() {
            return kind;
        }

        public void setKind(String kind) {
            this.kind = kind;
        }

    }

}
