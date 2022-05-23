package com.sap.cloud.extension.idp.utils;

import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialSupport;
import org.opensaml.security.crypto.KeySupport;
import java.security.*;

public class IdPCredentials {
    private static final Credential credential;

    static {
        credential = generateCredential();
    }

    private static Credential generateCredential() {
        try {
            KeyPair keyPair = KeySupport.generateKeyPair("RSA", 1024, null);
            return CredentialSupport.getSimpleCredential(keyPair.getPublic(), keyPair.getPrivate());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }

    public static Credential getCredential() {
        return credential;
    }

}
