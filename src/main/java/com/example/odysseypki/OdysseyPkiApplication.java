package com.example.odysseypki;

import com.example.odysseypki.certificate.CertificateGenerator;
import com.example.odysseypki.entity.Certificate;
import com.example.odysseypki.entity.Issuer;
import com.example.odysseypki.entity.Subject;
import com.example.odysseypki.keystore.KeyStoreReader;
import com.example.odysseypki.keystore.KeyStoreWriter;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ApplicationContext;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

@SpringBootApplication
public class OdysseyPkiApplication {

	public static final String CERT_KEYSTORE = "src/main/resources/static/certs.jks";

	public static void main(String[] args) {
		var context = SpringApplication.run(OdysseyPkiApplication.class, args);
		// demo(context);
	}

	public static void demo(ApplicationContext context) {
		var keyStoreReader = (KeyStoreReader) context.getBean("keyStoreReader");
		var keyStoreWriter = (KeyStoreWriter) context.getBean("keyStoreWriter");
		var secret = ((OdysseyPkiProperties) context.getBean("odysseyPkiProperties")).getSecret();

		var rootCert = generateRoot();

		System.out.println("Root certificate:");
		System.out.println(rootCert.getX509Certificate());

//		KEYSTORE CREATION REFERENCE (dodatno ne moramo)
//		try {
//			createKeyStore(CERT_KEYSTORE, secret);
//		} catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException e) {
//			e.printStackTrace();
//			return;
//		}

		// KEYSTORE REFERENCE

		keyStoreWriter.loadKeyStore(CERT_KEYSTORE, secret.toCharArray());
		keyStoreWriter.write("root", rootCert.getIssuer().getPrivateKey(), secret.toCharArray(), rootCert.getX509Certificate());
		keyStoreWriter.saveKeyStore(CERT_KEYSTORE, secret.toCharArray());
		System.out.println("Saved root to file.");

		System.out.println("Loading certificate:");
		var loadedCertificate = (X509Certificate) keyStoreReader.readCertificate(CERT_KEYSTORE, secret, "root");
		System.out.println(loadedCertificate);
	}

	public static void createKeyStore(String filepath, String secret) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
		KeyStore keyStore = KeyStore.getInstance("JKS");
		keyStore.load(null, null);
		try (FileOutputStream fos = new FileOutputStream(filepath)) {
			keyStore.store(fos, secret.toCharArray());
		}

	}

	// SERVICE METHODS

	public static Certificate generateRoot() {
		Issuer issuer = generateIssuer("root", "", "0");
		Subject subject = generateSubject("root", "", "0");

		Date startDate = new Date(2023, Calendar.APRIL, 15);
		Date endDate = new Date(2033, Calendar.APRIL, 15);

		X509Certificate certificate = CertificateGenerator.generateCertificate(subject,
				issuer, startDate, endDate, "1");

		return new Certificate(subject, issuer, "1", startDate, endDate, certificate);
	}

	public static Subject generateSubject(String commonName, String email, String uid) {
		KeyPair keyPairSubject = generateKeyPair();
		return new Subject(keyPairSubject.getPublic(), getX500Name(commonName, email, uid));
	}

	public static Issuer generateIssuer(String commonName, String email, String uid) {
		KeyPair kp = generateKeyPair();
		return new Issuer(kp.getPrivate(), kp.getPublic(), getX500Name(commonName, email, uid));
	}

	public static X500Name getX500Name(String commonName, String email, String uid) {
		X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
		builder.addRDN(BCStyle.CN, commonName);
		builder.addRDN(BCStyle.E, email);
		builder.addRDN(BCStyle.UID, uid);
		return builder.build();
	}

	public static KeyPair generateKeyPair() {
		try {
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
			SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
			keyGen.initialize(2048, random);
			return keyGen.generateKeyPair();
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			e.printStackTrace();
		}
		return null;
	}
}
