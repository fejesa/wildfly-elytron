package org.example.app;

import org.example.store.CredentialStoreRepository;

import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import java.security.GeneralSecurityException;
import java.util.Set;

/**
 * Used only for testing. Pls do not use it in real application.
 */
@Path("credentials")
public class CredentialStoreEndpoint {

    @Inject
    private CredentialStoreRepository credentialStoreRepository;

    @GET
    @Produces("application/json")
    public Set<String> getAliases() throws GeneralSecurityException {
        return credentialStoreRepository.getAliases();
    }

    @GET
    @Path("alias/{name}")
    public String getPassword(@PathParam("name") String alias) throws GeneralSecurityException {
        return credentialStoreRepository.getAliasPassword(alias);
    }
}
