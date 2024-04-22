package com.example.odysseypki;

import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Getter
@Component
public class OdysseyPkiProperties {
    @Value("${ODYSSEY_SECRET}")
    private String secret;
    @Value("${ODYSSEY_KEY_STORE_PATH}")
    private String keyStorePath;
    @Value("${ODYSSEY_KEY_STORE_PASSWORD}")
    private String keyStorePass;
    @Value("${ODYSSEY_CREATE_KEYSTORE}")
    private boolean initializeKeyStore;
}
