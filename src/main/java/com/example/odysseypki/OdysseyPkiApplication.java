package com.example.odysseypki;

import com.example.odysseypki.service.CertificateService;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.modelmapper.ModelMapper;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Security;

@SpringBootApplication
public class OdysseyPkiApplication {
	@Bean
	public ModelMapper getModelMapper() {
		return new ModelMapper();
	}

	public static void main(String[] args) throws GeneralSecurityException, IOException {
		Security.addProvider(new BouncyCastleProvider());
		var context = SpringApplication.run(OdysseyPkiApplication.class, args);

		var certificateService = (CertificateService) context.getBean("certificateService");
		var properties = (OdysseyPkiProperties) context.getBean("odysseyPkiProperties");

		if (properties.isInitializeKeyStore())
			certificateService.initializeKeyStore();
	}
}
