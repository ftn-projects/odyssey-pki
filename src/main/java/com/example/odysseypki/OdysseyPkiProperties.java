package com.example.odysseypki;

import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Getter
@Component
public class OdysseyPkiProperties {
    @Value("${ODYSSEY_SECRET}")
    private String secret;
}
