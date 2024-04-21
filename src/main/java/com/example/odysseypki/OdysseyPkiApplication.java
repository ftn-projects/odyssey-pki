package com.example.odysseypki;

import com.example.odysseypki.controller.CertificateController;
import org.modelmapper.ModelMapper;
import com.example.odysseypki.service.CertificateService;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.ssl.SslStoreBundle;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;

import java.security.Security;

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
		var controoller = (CertificateController) context.getBean("certificateController");

		try {
//			service.createRoot();
//			var rootAlias = service.getRootAlias();
//			System.out.println("Root alias: " + rootAlias);
//
			var response = controoller.findByAlias("1713699206615"); // trenutni root

			System.out.println(response);

//			service.delete("1713685566655"); // treba da pukne jer brise root

		} catch(Exception e) {
			e.printStackTrace();
		}
    }
}
