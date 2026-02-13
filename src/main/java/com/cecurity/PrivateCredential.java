package com.cecurity;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.HashSet;
import java.util.ArrayList;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.spec.ECGenParameterSpec;

import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.crypto.fips.FipsEC;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class PrivateCredential {
    private final X509Certificate certificate;
    private final PrivateKey privateKey;

    public PrivateCredential(X509Certificate certificate, PrivateKey privateKey) {
        this.certificate = certificate;
        this.privateKey = privateKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public X509Certificate getCertificate() {
        return certificate;
    }

    public static Date calculateDate(int hoursInFuture) {
        long secs = System.currentTimeMillis() / 1000;

        return new Date((secs + (hoursInFuture * 60 * 60)) * 1000);
    }

    private static long serialNumberBase = System.currentTimeMillis();


    public static synchronized BigInteger calculateSerialNumber() {
        return BigInteger.valueOf(serialNumberBase++);
    }


    /**
     * Build a sample self-signed V1 certificate to use as a trust anchor, or
     * root certificate.
     *
     * @param keyPair the key pair to use for signing and providing the
     *                public key.
     * @param sigAlg  the signature algorithm to sign the certificate with.
     * @return an X509CertificateHolder containing the V1 certificate.
     */
    public static X509CertificateHolder createTrustAnchor(
            KeyPair keyPair, String sigAlg)
            throws OperatorCreationException {
        X500NameBuilder x500NameBld = new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.C, "FR")
                .addRDN(BCStyle.ST, "France")
                .addRDN(BCStyle.L, "Paris")
                .addRDN(BCStyle.O, "Cecurity.com company")
                .addRDN(BCStyle.CN, "Demo Crypto Certificate");

        X500Name name = x500NameBld.build();

        X509v1CertificateBuilder certBldr = new JcaX509v1CertificateBuilder(
                name,
                calculateSerialNumber(),
                calculateDate(0),
                calculateDate(24 * 31),
                name,
                keyPair.getPublic());

        ContentSigner signer = new JcaContentSignerBuilder(sigAlg)
                .setProvider("BCFIPS").build(keyPair.getPrivate());

        return certBldr.build(signer);
    }

    public static PrivateCredential createSelfSignedCredentials()
            throws GeneralSecurityException, OperatorCreationException {
        JcaX509CertificateConverter certConverter =
                new JcaX509CertificateConverter().setProvider("BCFIPS");
        KeyPair selfSignedKp = generateECKeyPair("P-256");
        X509CertificateHolder selfSignedHldr =
                createTrustAnchor(selfSignedKp, "SHA256withECDSA");
        X509Certificate selfSignedCert = certConverter.getCertificate(selfSignedHldr);
        return new PrivateCredential(selfSignedCert, selfSignedKp.getPrivate());
    }

    /**
     * Generate a EC key pair on the passed in named curve.
     *
     * @param curveName the name of the curve to generate the key pair on.
     * @return a EC KeyPair
     */
    public static KeyPair generateECKeyPair(String curveName) throws GeneralSecurityException {
        KeyPairGenerator keyPair = KeyPairGenerator.getInstance("EC", "BCFIPS");

        keyPair.initialize(new ECGenParameterSpec(curveName));

        return keyPair.generateKeyPair();
    }

    public static PKIXCertPathValidatorResult validateCertPath(
            X509Certificate taCert, X509Certificate caCert, X509Certificate eeCert)
            throws GeneralSecurityException {
        List<X509Certificate> certchain = new ArrayList<X509Certificate>();
        certchain.add(eeCert);
        certchain.add(caCert);
        CertPath certPath = CertificateFactory.getInstance("X.509", "BCFIPS")
                .generateCertPath(certchain);
        Set<TrustAnchor> trust = new HashSet<TrustAnchor>();
        trust.add(new TrustAnchor(taCert, null));
        CertPathValidator certPathValidator = CertPathValidator.getInstance("PKIX", "BCFIPS");
        PKIXParameters param = new PKIXParameters(trust);
        param.setRevocationEnabled(false);
        param.setDate(new Date());
        return (PKIXCertPathValidatorResult) certPathValidator.validate(certPath, param);
    }

    public static PKIXCertPathValidatorResult validateCertPathWithCrl(
            X509Certificate taCert, X509CRL taCrl, X509Certificate caCert,
            X509CRL caCrl, X509Certificate eeCert)
            throws GeneralSecurityException {
        List<X509Certificate> certchain = new ArrayList<X509Certificate>();
        certchain.add(eeCert);
        certchain.add(caCert);
        CertPath certPath = CertificateFactory.getInstance("X.509", "BCFIPS")
                .generateCertPath(certchain);
        Set<TrustAnchor> trust = new HashSet<TrustAnchor>();
        trust.add(new TrustAnchor(taCert, null));
        Set crls = new HashSet();
        crls.add(caCrl);
        crls.add(taCrl);
        CertStore crlsStore = CertStore.getInstance("Collection",
                new CollectionCertStoreParameters(crls), "BCFIPS");
        CertPathValidator certPathValidator = CertPathValidator.getInstance("PKIX", "BCFIPS");
        PKIXParameters param = new PKIXParameters(trust);
        param.addCertStore(crlsStore);
        param.setDate(new Date());
        return (PKIXCertPathValidatorResult) certPathValidator.validate(certPath, param);
    }

    /**
     * Simple method to convert an X509CertificateHolder to an X509Certificate
     * using the java.security.cert.CertificateFactory class.
     */
    public static X509Certificate convertX509CertificateHolder(
            X509CertificateHolder certHolder)
            throws GeneralSecurityException, CertificateException, NoSuchProviderException, IOException {
        try {
            CertificateFactory cFact = CertificateFactory.getInstance("X.509", "BC");

            var cert = (X509Certificate) cFact.generateCertificate(
                    new ByteArrayInputStream(
                            certHolder.getEncoded()));
            return cert;
        } catch (CertificateException | NoSuchProviderException | IOException e) {
            throw new GeneralSecurityException("Failed to convert X509CertificateHolder", e);
        }
    }
}
