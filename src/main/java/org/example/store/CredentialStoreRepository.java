package org.example.store;

import java.security.GeneralSecurityException;
import java.util.Set;

public interface CredentialStoreRepository {

    String getAliasPassword(String alias) throws GeneralSecurityException;

    Set<String> getAliases() throws GeneralSecurityException;
}
