package com.codeslab.sslgenerator;

import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;

import java.io.FileOutputStream;
import java.math.BigInteger;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 *
 */
public class SelfSignedCertificateGenerator {

    private final static CertificateConverter mCertificateConverter = new CertificateConverter();
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        // Generate key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // Generate self-signed certificate
        X509Certificate cert = generateSelfSignedCertificate(keyPair);

        // Save certificate and private key to files
        //saveCertificateToFile(cert, "certificate.cert");
        //savePrivateKeyToFile(keyPair.getPrivate(), "key.pem");
        mCertificateConverter.saveCertificateAndDetailsToFile(cert, keyPair.getPrivate(), Path.of("./"));

        System.out.println("Self-signed certificate and key pair generated successfully.");
    }

    private static X509Certificate generateSelfSignedCertificate(KeyPair keyPair)
        throws CertificateEncodingException, InvalidKeyException, NoSuchProviderException, NoSuchAlgorithmException, SignatureException {
        X509V3CertificateGenerator certGenerator = new X509V3CertificateGenerator();

        // Certificate information
        certGenerator.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
        certGenerator.setIssuerDN(new X509Name("CN=Self-Signed Certificate"));
        certGenerator.setSubjectDN(new X509Name("CN=Self-Signed Certificate"));
        certGenerator.setNotBefore(new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000)); // 1 day before
        certGenerator.setNotAfter(new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000)); // 1 year later
        certGenerator.setPublicKey(keyPair.getPublic());
        certGenerator.setSignatureAlgorithm("SHA256WithRSAEncryption");

        // Generate certificate
        return certGenerator.generate(keyPair.getPrivate(), "BC");
    }

    private static void saveCertificateToFile(X509Certificate cert, String filename) throws CertificateException {
        try (FileOutputStream fos = new FileOutputStream(filename)) {
            fos.write(cert.getEncoded());
        } catch (Exception e) {
            throw new CertificateException("Failed to save certificate to file", e);
        }
    }

    private static void savePrivateKeyToFile(PrivateKey privateKey, String filename) throws Exception {
        try (FileOutputStream fos = new FileOutputStream(filename)) {
            fos.write(privateKey.getEncoded());
        } catch (Exception e) {
            throw new Exception("Failed to save private key to file", e);
        }
    }

}
