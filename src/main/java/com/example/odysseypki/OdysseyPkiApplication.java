package com.example.odysseypki;

import com.example.odysseypki.controller.CertificateController;
import com.example.odysseypki.entity.Certificate;
import org.modelmapper.ModelMapper;
import com.example.odysseypki.service.CertificateService;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.ssl.SslStoreBundle;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;

import java.security.Security;
import java.util.*;

@SpringBootApplication
public class OdysseyPkiApplication {
	@Bean
	public ModelMapper getModelMapper() {
		return new ModelMapper();
	}

	public static void main(String[] args) {
		Security.addProvider(new BouncyCastleProvider());
		var context = SpringApplication.run(OdysseyPkiApplication.class, args);

		demo(context);
	}

	public static void demo(ApplicationContext context) {
		var service = (CertificateService) context.getBean("certificateService");
		var controller = (CertificateController) context.getBean("certificateController");
		var allKeyUsages = Arrays.stream(Certificate.KeyUsageValue.values()).map(Certificate.KeyUsageValue::name).toList();
		try {

			// ROOT CREATION
//
//			service.createRoot();
//			var rootAlias = service.getRootAlias();
//			System.out.println("Root alias: " + rootAlias);

//			var created = service.create(
//					"1713719148359", "DIMITRIJEOTVORIOCI ", "NOVO@gmail.com", "AAAAA",
//					new Date(2024, 1, 1), new Date(2034, 1, 1), Map.of(
////							Certificate.Extension.BASIC_CONSTRAINTS, List.of(String.valueOf(false)),
////							Certificate.Extension.KEY_USAGE, allKeyUsages,
////							Certificate.Extension.SUBJECT_KEY_IDENTIFIER, List.of(),
////							Certificate.Extension.AUTHORITY_KEY_IDENTIFIER, List.of()
//					)
//			);
//
//			System.out.println("Created: " + created.getAlias());

		} catch(Exception e) {
			e.printStackTrace();
		}
    }
}
