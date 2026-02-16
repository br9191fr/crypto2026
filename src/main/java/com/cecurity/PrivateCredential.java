package com.cecurity;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.Extension.*;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.X509CRL;
import java.security.cert.CertPathValidator;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.CertificateException;
import java.security.cert.CertPath;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;

import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.HashSet;
import java.util.ArrayList;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.spec.ECGenParameterSpec;


import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;

public record PrivateCredential(X509Certificate certificate, PrivateKey privateKey) {

    private static long serialNumberBase;// = System.currentTimeMillis();
    static {
        serialNumberBase = System.currentTimeMillis();
    }
    public static Date calculateDate(int hoursInFuture) {
        long secs = System.currentTimeMillis() / 1000;

        return new Date((secs + ((long) hoursInFuture * 60 * 60)) * 1000);
    }

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
        List<X509Certificate> certchain = new ArrayList<>();
        certchain.add(eeCert);
        certchain.add(caCert);
        CertPath certPath = CertificateFactory.getInstance("X.509", "BCFIPS")
                .generateCertPath(certchain);
        Set<TrustAnchor> trust = new HashSet<>();
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
        List<X509Certificate> certchain = new ArrayList<>();
        certchain.add(eeCert);
        certchain.add(caCert);
        CertPath certPath = CertificateFactory.getInstance("X.509", "BCFIPS")
                .generateCertPath(certchain);
        Set<TrustAnchor> trust = new HashSet<>();
        trust.add(new TrustAnchor(taCert, null));
        HashSet crls = new HashSet();
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
            throws GeneralSecurityException, IOException {
        try {
            CertificateFactory cFact = CertificateFactory.getInstance("X.509", "BC");

            return (X509Certificate) cFact.generateCertificate(
                    new ByteArrayInputStream(
                            certHolder.getEncoded()));
        } catch (CertificateException | NoSuchProviderException | IOException e) {
            throw new GeneralSecurityException("Failed to convert X509CertificateHolder", e);
        }
    }

    /**
     * Extract the DER encoded value octets of an extension from a JCA
     * X509Certificate.
     *
     * @param cert         the certificate of interest.
     * @param extensionOID the OID associated with the extension of interest.
     * @return the DER encoding inside the extension, null if extension missing.
     * 8
     */
    public static byte[] extractExtensionValue(
            X509Certificate cert,
            ASN1ObjectIdentifier extensionOID) {
        byte[] octString = cert.getExtensionValue(extensionOID.getId());

        if (octString == null) {
            return null;
        }

        return ASN1OctetString.getInstance(octString).getOctets();
    }

    /**
     * Build a sample V3 intermediate certificate that can be used as a CA
     * certificate.
     *
     * @param signerCert       certificate carrying the public key that will later
     *                         be used to verify this certificate's signature.
     * @param signerKey        private key used to generate the signature in the
     *                         certificate.
     * @param sigAlg           the signature algorithm to sign the certificate with.
     * @param certKey          public key to be installed in the certificate.
     * @param followingCACerts
     * @return an X509CertificateHolder containing the V3 certificate.
     */
    public static X509CertificateHolder createIntermediateCertificate(
            X509CertificateHolder signerCert, PrivateKey signerKey,
            String sigAlg, PublicKey certKey, int followingCACerts)
            throws CertIOException, GeneralSecurityException,
            OperatorCreationException {
        X500NameBuilder x500NameBld = new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.C, "AU")
                .addRDN(BCStyle.ST, "Victoria")
                .addRDN(BCStyle.L, "Melbourne")
                .addRDN(BCStyle.O, "The Legion of the Bouncy Castle")
                .addRDN(BCStyle.CN, "Demo Intermediate Certificate");

        X500Name subject = x500NameBld.build();

        X509v3CertificateBuilder certBldr = new JcaX509v3CertificateBuilder(
                signerCert.getSubject(),
                calculateSerialNumber(),
                calculateDate(0),
                calculateDate(24 * 31),
                subject,
                certKey);

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        certBldr.addExtension(Extension.authorityKeyIdentifier,
                        false, extUtils.createAuthorityKeyIdentifier(signerCert))
                .addExtension(Extension.subjectKeyIdentifier,
                        false, extUtils.createSubjectKeyIdentifier(certKey))
                .addExtension(Extension.basicConstraints,
                        true, new BasicConstraints(followingCACerts))
                .addExtension(Extension.keyUsage,
                        true, new KeyUsage(
                                KeyUsage.digitalSignature
                                        | KeyUsage.keyCertSign
                                        | KeyUsage.cRLSign));

        ContentSigner signer = new JcaContentSignerBuilder(sigAlg)
                .setProvider("BCFIPS").build(signerKey);

        return certBldr.build(signer);
    }
    /**
     * Create a general end-entity certificate for use in verifying digital
     * signatures.
     *
     * @param signerCert certificate carrying the public key that will later
     * be used to verify this certificate's signature.
     * @param signerKey private key used to generate the signature in the
     * certificate.
     * @param sigAlg the signature algorithm to sign the certificate with.
     * @param certKey public key to be installed in the certificate.
     * @return an X509CertificateHolder containing the V3 certificate.
     */
    public static X509CertificateHolder createEndEntity(
            X509CertificateHolder signerCert, PrivateKey signerKey,
            String sigAlg, PublicKey certKey)
            throws CertIOException, GeneralSecurityException,
            OperatorCreationException
    {
        X500NameBuilder x500NameBld = new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.C, "AU")
                .addRDN(BCStyle.ST, "Victoria")
                .addRDN(BCStyle.L, "Melbourne")
                .addRDN(BCStyle.O, "The Legion of the Bouncy Castle")
                .addRDN(BCStyle.CN, "Demo End-Entity Certificate");
        X500Name subject = x500NameBld.build();
        X509v3CertificateBuilder certBldr = new JcaX509v3CertificateBuilder(
                signerCert.getSubject(),
                calculateSerialNumber(),
                calculateDate(0),
                calculateDate(24 * 31),
                subject,
                certKey);
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        certBldr.addExtension(Extension.authorityKeyIdentifier,
                        false, extUtils.createAuthorityKeyIdentifier(signerCert))
                .addExtension(Extension.subjectKeyIdentifier,
                        false, extUtils.createSubjectKeyIdentifier(certKey))
                .addExtension(Extension.basicConstraints,
                        true, new BasicConstraints(false))
                .addExtension(Extension.keyUsage,
                        true, new KeyUsage(KeyUsage.digitalSignature));
        ContentSigner signer = new JcaContentSignerBuilder(sigAlg)
                .setProvider("BC").build(signerKey);
        return certBldr.build(signer);
    }
}
