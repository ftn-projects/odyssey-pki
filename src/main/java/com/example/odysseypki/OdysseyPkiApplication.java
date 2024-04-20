package com.example.odysseypki;

import com.example.odysseypki.certificate.CertificateGenerator;
import com.example.odysseypki.entity.Certificate;
import com.example.odysseypki.entity.Issuer;
import com.example.odysseypki.entity.Subject;
import com.example.odysseypki.keystore.KeyStoreReader;
import com.example.odysseypki.keystore.KeyStoreWriter;
import com.example.odysseypki.service.CertificateService;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ApplicationContext;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Calendar;
import java.util.Date;

@SpringBootApplication
public class OdysseyPkiApplication {

	public static final String CERT_KEYSTORE = "src/main/resources/static/certs.jks";

	public static void main(String[] args) {
		var context = SpringApplication.run(OdysseyPkiApplication.class, args);

//		//For testing, delete after testing is done -Arezinko
//		CertificateTree tree = new CertificateTree(new CertificateNode("root"));
//		tree.generateDummyCertificates(10);
//		System.out.println("=========\nOLD TREE\n=========");
//		tree.printTree();
//		tree.serialize(filepath);
//
//		//CertificateNode node = tree.findByAlias("Certificate2");
//
//		List<String> removedAliases = tree.removeCertificate("Certificate2");
//		System.out.println("=========\nNEW TREE\n=========");
//		tree.printTree();
//		System.out.println("Removed Aliases: " + removedAliases);

		 demo(context);
	}

	public static void demo(ApplicationContext context) {
		var service = (CertificateService) context.getBean("certificateService");

		try {
//			service.generateRoot();

			var cert = service.get("1713612128531");

//			service.add(
//					"0",
//					"Ivana Kovacevic",
//					"ivana@gmail.com",
//					"123",
//					new Date(2024, Calendar.JANUARY, 1),
//					new Date(2034, Calendar.JANUARY, 1));

			System.out.println(cert.getSerialNumber());

		} catch( Exception e) {
			e.printStackTrace();
		}
    }
}
