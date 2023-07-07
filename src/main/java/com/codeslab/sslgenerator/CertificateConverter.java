package com.codeslab.sslgenerator;

import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Base64;

/**
 *
 */
public class CertificateConverter {

    private static final int LINE_LENGTH = 64;
    private static final String CERT_FILE_NAME = "certificate.crt";
    private static final String PRIVATE_KEY_FILE_NAME = "privateKey.pem";
    private static final String BEGIN_CERT = "-----BEGIN CERTIFICATE-----";
    private static final String END_CERT = "-----END CERTIFICATE-----";
    private static final String BEGIN_KEY = "-----BEGIN PRIVATE KEY-----";
    private static final String END_KEY = "-----END PRIVATE KEY-----";
    private final static String LINE_SEPARATOR = System.getProperty("line.separator");
    final static Base64.Encoder BASE64_ENCODER = Base64.getMimeEncoder(LINE_LENGTH, LINE_SEPARATOR.getBytes());

    // ------------------------------------------------------------------------
    // methods
    // ------------------------------------------------------------------------

    public void saveCertificateAndDetailsToFile(X509Certificate certificate, PrivateKey privateKey, Path path) throws Exception {
        this.saveCertificateToFile(certificate, this.resolvePath(path, CERT_FILE_NAME));
        this.savePrivateKeyToFile(privateKey, this.resolvePath(path, PRIVATE_KEY_FILE_NAME));
    }

    private void saveCertificateToFile(X509Certificate cert, Path filePath) throws Exception {
        this.saveToFile(this.formatCrtFileContents(cert), filePath);
    }

    private void savePrivateKeyToFile(PrivateKey privateKey, Path filePath) throws Exception {
        this.saveToFile(this.formatPrivateKeyFileContents(privateKey), filePath);
    }

    private byte[] formatCrtFileContents(X509Certificate certificate) throws CertificateEncodingException {
        final String encodedCertText = new String(BASE64_ENCODER.encode(certificate.getEncoded()));
        final String prettified_cert = BEGIN_CERT + LINE_SEPARATOR + encodedCertText + LINE_SEPARATOR + END_CERT;
        return prettified_cert.getBytes();
    }

    private byte[] formatPrivateKeyFileContents(PrivateKey privateKey) {
        final String encodedKeyText = new String(BASE64_ENCODER.encode(privateKey.getEncoded()));
        final String prettified_key = BEGIN_KEY + LINE_SEPARATOR + encodedKeyText + LINE_SEPARATOR + END_KEY;
        return prettified_key.getBytes();
    }

    private void saveToFile(byte[] content, Path filePath) throws Exception {
        try (FileOutputStream fos = new FileOutputStream(filePath.toString())) {
            fos.write(content);
        } catch (Exception e) {
            throw new Exception("Error while writing certificate/key to files", e);
        }
    }

    private Path resolvePath(Path path, String fileName) {
        return path.resolve(fileName);
    }

    public boolean isCertificatePresent(Path path) {
        return Files.exists(this.resolvePath(path, CERT_FILE_NAME));
    }

}
