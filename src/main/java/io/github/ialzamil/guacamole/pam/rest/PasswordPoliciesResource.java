package io.github.ialzamil.guacamole.pam.rest;

import java.util.ArrayList;
import java.util.LinkedHashMap;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.github.ialzamil.guacamole.pam.PamAuthenticationProvider;
import io.github.ialzamil.guacamole.pam.Values;
import io.github.ialzamil.guacamole.pam.password.PasswordGenerator;
import io.github.ialzamil.guacamole.pam.password.PasswordPolicy;
import io.github.ialzamil.guacamole.pam.password.PasswordRules;

/**
 * Password policies, at "password-policies": their names readable by any
 * user, for the connection editor; everything else is limited to
 * administrators.
 */
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class PasswordPoliciesResource extends PamResource {

    private static final Logger logger = LoggerFactory.getLogger(PasswordPoliciesResource.class);

    /**
     * How many example passwords the password policy editor shows.
     */
    private static final int EXAMPLE_PASSWORDS = 3;

    private final PasswordGenerator passwordGenerator = new PasswordGenerator();

    PasswordPoliciesResource(PamAuthenticationProvider provider, AuthenticatedUser user) {
        super(provider, user);
    }

    /**
     * All password policies. Any user gets names, for the connection editor;
     * administrators also get rules, and what uses each.
     */
    @GET
    public List<PasswordPolicy> listPasswordPolicies() throws GuacamoleException {
        List<PasswordPolicy> policies = provider.getPasswordPolicies().list();
        if (!isAdministrator()) {
            for (PasswordPolicy policy : policies) {
                policy.setRules(null);
                policy.setPlatforms(null);
                policy.setConnections(null);
                policy.setDescription(null);
            }
        }
        return policies;
    }

    /**
     * The rules of passwords without a password policy, as the editor shows
     * them.
     */
    @GET
    @Path("default")
    public PasswordRules getDefaultPasswordRules() throws GuacamoleException {
        requireAdministrator();
        return PasswordRules.defaults().validate();
    }

    @POST
    public PasswordPolicy createPasswordPolicy(PasswordPolicy policy) throws GuacamoleException {
        requireAdministrator();
        PasswordPolicy created = provider.getPasswordPolicies().create(policy);
        logger.info("User \"{}\" created password policy \"{}\".", username(), Values.forLog(created.getName()));
        return created;
    }

    @PUT
    @Path("{id}")
    public PasswordPolicy updatePasswordPolicy(@PathParam("id") String id, PasswordPolicy policy)
            throws GuacamoleException {
        requireAdministrator();
        PasswordPolicy updated = provider.getPasswordPolicies().update(parseId(id), policy);
        logger.info("User \"{}\" updated password policy \"{}\".", username(), Values.forLog(updated.getName()));
        return updated;
    }

    @DELETE
    @Path("{id}")
    public void deletePasswordPolicy(@PathParam("id") String id) throws GuacamoleException {
        requireAdministrator();
        PasswordPolicy policy = provider.getPasswordPolicies().get(parseId(id));
        if (policy == null)
            throw new GuacamoleResourceNotFoundException("No such password policy.");
        provider.getPasswordPolicies().delete(policy.getId());
        logger.info("User \"{}\" deleted password policy \"{}\".", username(), Values.forLog(policy.getName()));
    }

    /**
     * Examples of passwords the given rules make, saved or not, and their
     * strength: bits of randomness, from how many characters each is drawn
     * from.
     */
    @POST
    @Path("examples")
    public Map<String, Object> examplePasswords(PasswordRules rules) throws GuacamoleException {
        requireAdministrator();
        if (rules == null)
            throw new GuacamoleClientException("There are no rules.");
        rules.validate();
        List<String> examples = new ArrayList<>();
        for (int i = 0; i < EXAMPLE_PASSWORDS; i++)
            examples.add(passwordGenerator.generate(rules));
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("examples", examples);
        result.put("bits", PasswordGenerator.strengthBits(rules));
        return result;
    }

}
