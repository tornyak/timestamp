package com.tornyak.pki;

import java.security.*;

public class TestKeyProvider implements KeyProvider {

    private final KeyPair keyPair;

    TestKeyProvider(KeyPair keyPair) {
        this.keyPair = keyPair;
    }

    public PrivateKey getPrivateKey() throws GeneralSecurityException {
        return keyPair.getPrivate();
    }
}
