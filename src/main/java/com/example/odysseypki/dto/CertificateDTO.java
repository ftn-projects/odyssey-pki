package com.example.odysseypki.dto;

import com.example.odysseypki.entity.Certificate;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import org.bouncycastle.asn1.x509.Extension;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.Dictionary;
import java.util.List;
import java.util.Map;

@Getter
@Setter
@AllArgsConstructor
public class CertificateDTO {
    private String alias;
    private String parentAlias;
    private Map<String, String> issuer;
    private Map<String, String> subject;
    private Validity validity;
    private PublicKey publicKey;
    private List<Extension> extensions;
    private Signature signature;

    @Getter
    @AllArgsConstructor
    public static class Validity {
        private LocalDateTime start;
        private LocalDateTime end;

        public Validity(X509Certificate certificate) {
            this.start = LocalDateTime.ofInstant(
                    certificate.getNotBefore().toInstant(), ZoneId.systemDefault());
            this.end = LocalDateTime.ofInstant(
                    certificate.getNotAfter().toInstant(), ZoneId.systemDefault());
        }
    }

    @Getter
    @AllArgsConstructor
    public static class PublicKey {
        private String format;
        private String algorithm;
        private byte[] encoded;

        public PublicKey(X509Certificate certificate) {
            this.format = certificate.getPublicKey().getFormat();
            this.algorithm = certificate.getPublicKey().getAlgorithm();
            this.encoded = certificate.getPublicKey().getEncoded();
        }
    }

    @Getter
    @AllArgsConstructor
    public static class Extension {
        private String name;
        private boolean critical;
        private List<Object> values;
    }

    @Getter
    @AllArgsConstructor
    public static class Signature {
        private String algorithm;
        private byte[] value;

        public Signature(X509Certificate certificate) {
            this.algorithm = certificate.getSigAlgName();
            this.value = certificate.getSignature();
        }
    }
}
