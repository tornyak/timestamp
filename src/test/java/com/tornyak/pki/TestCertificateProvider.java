package com.tornyak.pki;

import java.security.cert.X509Certificate;

public class TestCertificateProvider implements CertificateProvider {
    private X509Certificate cert;

    TestCertificateProvider(X509Certificate cert) {
        this.cert = cert;
    }

    @Override
    public X509Certificate getCertificate() {
        return cert;
    }
}
