package com.tornyak.pki;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;

public interface KeyProvider {
    PrivateKey getPrivateKey() throws GeneralSecurityException;
}
