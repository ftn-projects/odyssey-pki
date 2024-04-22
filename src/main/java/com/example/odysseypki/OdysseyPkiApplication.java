package com.example.odysseypki;

import com.example.odysseypki.service.CertificateService;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.modelmapper.ModelMapper;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.attribute.*;
import java.security.Security;

@SpringBootApplication
public class OdysseyPkiApplication {
	@Bean
	public ModelMapper getModelMapper() {
		return new ModelMapper();
	}

	public static void main(String[] args) throws IOException {
		Security.addProvider(new BouncyCastleProvider());
		var context = SpringApplication.run(OdysseyPkiApplication.class, args);

		var certificateService = (CertificateService) context.getBean("certificateService");
		var properties = (OdysseyPkiProperties) context.getBean("odysseyPkiProperties");

		if (properties.isInitializeKeyStore())
			certificateService.initializeKeyStore();

		// printAclInfo(properties.getKeyStorePath());
	}

	public static void printAclInfo(String filepath) throws IOException {
		// Echo ACL
		var view = Files.getFileAttributeView(Paths.get(filepath), AclFileAttributeView.class);

		for (AclEntry entry : view.getAcl()) {
			System.out.println("=== flags ===");

			for (AclEntryFlag flags : entry.flags())
				System.out.println(flags.name());

			System.out.println("=== permissions ===");
			for (AclEntryPermission permission : entry.permissions())
				System.out.println(permission.name());
		}
	}
}
