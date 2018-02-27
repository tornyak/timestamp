package com.tornyak.pki;

import java.security.cert.X509Certificate;

public interface CertificateProvider {
    X509Certificate getCertificate();
}
