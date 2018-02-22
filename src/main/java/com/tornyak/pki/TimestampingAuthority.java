package com.tornyak.pki;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;

/**
 * PKI notary providing secure timestamping service
 */
public class TimestampingAuthority {

    private X509Certificate certificate;
    private PrivateKey privateKey;

    public TimestampingAuthority(X509Certificate certificate, PrivateKey privateKey) {
        this.certificate = certificate;
        this.privateKey = privateKey;
    }

    public byte[] sign(byte[] data) throws GeneralSecurityException, CMSException, IOException, OperatorCreationException {
        Security.addProvider(new BouncyCastleProvider());
        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        generator.addCertificate(new X509CertificateHolder(certificate.getEncoded()));
        ContentSigner signer = new JcaContentSignerBuilder("SHA512withRSA").setProvider(BouncyCastleProvider.PROVIDER_NAME).build(privateKey);

        generator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
                new JcaDigestCalculatorProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build())
                .build(signer, certificate));

        CMSTypedData content = new CMSProcessableByteArray(data);
        CMSSignedData signedData = generator.generate(content, true);
        return signedData.getEncoded();
    }
}
