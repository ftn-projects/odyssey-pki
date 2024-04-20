package com.example.odysseypki;

import org.modelmapper.ModelMapper;
import com.example.odysseypki.service.CertificateService;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;

import java.security.Security;

@SpringBootApplication
public class OdysseyPkiApplication {
	@Bean
	public ModelMapper getModelMapper() {
		return new ModelMapper();
	}
	public static final String CERT_KEYSTORE = "src/main/resources/static/certs.jks";

	public static void main(String[] args) {
		Security.addProvider(new BouncyCastleProvider());
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

			var cert = service.find("1713612128531");

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
