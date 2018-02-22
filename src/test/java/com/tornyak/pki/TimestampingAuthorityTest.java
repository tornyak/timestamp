package com.tornyak.pki;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;

import static java.time.temporal.ChronoUnit.DAYS;
import static org.junit.Assert.assertNotNull;


public class TimestampingAuthorityTest {

    private static final String TEXT = "THE QUICK BROWN FOX JUMPED OVER THE LAZY DOG'S BACK 1234567890";

    @Test
    public void sign() throws Exception {
        KeyPair keyPair = generateKeyPair();
        X509Certificate cert = createCertificate(keyPair);
        TimestampingAuthority ta = new TimestampingAuthority(cert, keyPair.getPrivate());
        byte[] signedData = ta.sign(generateHash());
        assertNotNull(signedData);
        System.out.println(new String(Hex.encode(signedData)));
    }

    private static byte[] generateHash() throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-512");
        return digest.digest(TEXT.getBytes(StandardCharsets.UTF_8));
    }

    private static X509Certificate createCertificate(KeyPair keyPair) throws NoSuchAlgorithmException, OperatorCreationException, CertificateException {
        Date start = Date.from(Instant.now());
        Date expiry = Date.from(Instant.now().plus(1, DAYS));
        BigInteger serialNumber = BigInteger.ONE;
        X500Name name = new X500Name("CN=Test V3 Certificate");
        X509v3CertificateBuilder certificateBuilder = new X509v3CertificateBuilder(name, serialNumber,
                start, expiry, name, SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded()));
        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA").setProvider(new BouncyCastleProvider()).build(keyPair.getPrivate());
        X509CertificateHolder holder = certificateBuilder.build(signer);
        return new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider()).getCertificate(holder);
    }

    private static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        return keyGen.generateKeyPair();
    }
}
