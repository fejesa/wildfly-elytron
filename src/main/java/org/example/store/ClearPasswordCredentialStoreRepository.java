package org.example.store;

import org.jboss.as.controller.client.ModelControllerClient;
import org.jboss.as.controller.client.OperationBuilder;
import org.jboss.as.controller.client.helpers.ClientConstants;
import org.jboss.dmr.ModelNode;
import org.jboss.dmr.Property;
import org.wildfly.security.auth.server.IdentityCredentials;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.credential.store.CredentialStoreException;
import org.wildfly.security.credential.store.WildFlyElytronCredentialStoreProvider;
import org.wildfly.security.password.WildFlyElytronPasswordProvider;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.util.PasswordBasedEncryptionUtil;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import java.io.IOException;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.*;

/**
 * Provides read access to configured credential store. We expect that
 * <ul>
 * <li>the name of the store is ExampleCredentialStore</li>
 * <li>keystore type is JCEKS (Java Cryptography Extension KeyStore)</li>
 * <li>the store file is protected with a masked password</li>
 * <li>the store file is relatively stored on the <i>jboss.server.config.dir</i></li>
 * </ul>
 * like:
 * <pre>
 * {@code
 * <credential-stores>
 *    <credential-store name="ExampleCredentialStore" relative-to="jboss.server.config.dir" path="the-store-file.jceks">
 *       <credential-reference clear-text="MASK-1xpIKc1tTnknw8W2VlMRar;12345678;100"/>
 *    </credential-store>
 * </credential-stores>
 * }
 * </pre>
 */
@ApplicationScoped
public class ClearPasswordCredentialStoreRepository implements CredentialStoreRepository {

    /** The unique name of the credential store in the configuration. */
    private static final String CREDENTIAL_STORE_NAME = "ExampleCredentialStore";

    /**
     * Fetch the clear password of the given alias
     * @return The clear text password or empty if the alias is not exist
     */
    @Override
    public String getAliasPassword(String alias) throws GeneralSecurityException {
        var credentialStore = getCredentialStore(getCredentialStoreAttributes());
        return Optional.ofNullable(credentialStore.retrieve(alias, PasswordCredential.class))
                .map(PasswordCredential::getPassword)
                .map(p -> (ClearPassword) p)
                .map(ClearPassword::getPassword)
                .map(String::new).orElse("");
    }

    @Override
    public Set<String> getAliases() throws GeneralSecurityException {
        return getCredentialStore(getCredentialStoreAttributes()).getAliases();
    }

    @PostConstruct
    private void init() {
        // Registers Elytron password provider
        Security.addProvider(new WildFlyElytronPasswordProvider());
    }

    private CredentialStoreAttributes getCredentialStoreAttributes() {
        // Fetch the Credential Store configuration attributes by using Wildfly application server management API
        try (var client = ModelControllerClient
                .Factory.create("127.0.0.1", 9990)) {
            var request = createElytronRequest();
            var response = client.execute(new OperationBuilder(request).build());
            var result = response.get(ClientConstants.RESULT).get("credential-store").asList();

            return getCredentialStoreAttributes(result);

        } catch (IOException | GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    private CredentialStore getCredentialStore(CredentialStoreAttributes credentialStoreAttributes) throws NoSuchAlgorithmException, CredentialStoreException {
        var storePassword = ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR, credentialStoreAttributes.getKeystorePassword());
        var protectionParameter = new CredentialStore.CredentialSourceProtectionParameter(
                IdentityCredentials.NONE.withCredential(
                        new PasswordCredential(storePassword)));
        var credentialStore = CredentialStore.getInstance(
                "KeyStoreCredentialStore", new WildFlyElytronCredentialStoreProvider());
        credentialStore.initialize(getKeystoreAttributes(credentialStoreAttributes.getKeystorePath()), protectionParameter);
        return credentialStore;
    }

    private Map<String, String> getKeystoreAttributes(String keystorePath) {
        return Map.of(
                "location", keystorePath,
                "keyStoreType", "JCEKS",
                "modifiable", "false");
    }

    private CredentialStoreAttributes getCredentialStoreAttributes(List<ModelNode> storeList) throws GeneralSecurityException {
        var path = getKeystorePath(storeList);
        var password = getCredentialStoreUnmaskedPassword(getCredentialStoreMaskedPassword(storeList));

        return new CredentialStoreAttributes(System.getProperty("jboss.server.config.dir"), path, password);
    }

    /**
     * Decrypt the credential store masked password
     */
    private char[] getCredentialStoreUnmaskedPassword(String maskedPassword) throws GeneralSecurityException {
        var passwordAttributes = getMaskedPasswordAttributes(maskedPassword);
        var encryptUtil = new PasswordBasedEncryptionUtil.Builder()
                .picketBoxCompatibility()
                .salt(passwordAttributes.getSalt())
                .iteration(passwordAttributes.getIteration())
                .decryptMode()
                .build();
        return encryptUtil.decodeAndDecrypt(passwordAttributes.getEncoded());
    }

    /**
     * Split the masked password
     */
    private MaskedPasswordAttributes getMaskedPasswordAttributes(String maskedPassword) {
        var maskLength = "MASK-".length();
        if (maskedPassword.length() <= maskLength) {
            throw new IllegalArgumentException("Masked password is not valid format");
        }
        var parsed = maskedPassword.substring(maskLength).split(";");
        if (parsed.length != 3) {
            throw new IllegalArgumentException("Masked password is not valid format");
        }
        var encoded = parsed[0];
        var salt = parsed[1];
        var iteration = Integer.parseInt(parsed[2]);

        return new MaskedPasswordAttributes(encoded, salt, iteration);
    }

    private String getCredentialStoreMaskedPassword(List<ModelNode> storeList) throws GeneralSecurityException {
        return findCredentialStore(storeList)
                .map(v -> v.get("credential-reference"))
                .map(v -> v.get("clear-text"))
                .map(ModelNode::asString)
                .orElseThrow(() -> new GeneralSecurityException("Missing MedATCredentialStore masked password"));
    }

    private String getKeystorePath(List<ModelNode> storeList) throws GeneralSecurityException {
        return findCredentialStore(storeList)
                .map(ModelNode::asPropertyList)
                .stream()
                .flatMap(Collection::stream)
                .filter(n -> n.getName().equals("path"))
                .map(Property::getValue)
                .map(ModelNode::asString)
                .findAny()
                .orElseThrow(() -> new GeneralSecurityException("Missing path store attribute"));
    }

    /**
     * Find the ExampleCredentialStore from the configuration
     */
    private Optional<ModelNode> findCredentialStore(List<ModelNode> storeList) {
        return storeList.stream()
                .map(ModelNode::asProperty)
                .filter(p -> CREDENTIAL_STORE_NAME.equals(p.getName()))
                .map(Property::getValue).findAny();
    }

    /**
     * Create a read request to get the configuration of the Elytron subsystem
     */
    private ModelNode createElytronRequest() {
        var request = new ModelNode();
        request.get(ClientConstants.OP).set("read-resource");
        request.get("recursive").set(true);
        request.get(ClientConstants.OP_ADDR).add("subsystem", "elytron");
        return request;
    }

    private static class CredentialStoreAttributes {

        private final String keystorePath;

        private final char[] keystorePassword;

        public CredentialStoreAttributes(String relativeTo, String path, char[] keystorePassword) {
            Objects.requireNonNull(relativeTo, "Keystore relative path must be set");
            Objects.requireNonNull(path, "Keystore path must be set");
            Objects.requireNonNull(keystorePassword, "Keystore password must be set");
            this.keystorePath = Paths.get(relativeTo).resolve(path).toAbsolutePath().toString();
            this.keystorePassword = keystorePassword;
        }

        public String getKeystorePath() {
            return keystorePath;
        }

        public char[] getKeystorePassword() {
            return keystorePassword;
        }
    }

    private static class MaskedPasswordAttributes {

        private final String encoded;

        private final String salt;

        private final int iteration;

        public MaskedPasswordAttributes(String encoded, String salt, int iteration) {
            Objects.requireNonNull(encoded, "Encoded part must be set");
            Objects.requireNonNull(salt, "Password salt must be set");
            if (iteration <= 0) {
                throw new IllegalArgumentException("Iteration count must be positive");
            }
            this.encoded = encoded;
            this.salt = salt;
            this.iteration = iteration;
        }

        public String getEncoded() {
            return encoded;
        }

        public String getSalt() {
            return salt;
        }

        public int getIteration() {
            return iteration;
        }
    }
}
