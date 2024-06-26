package com.example.odysseypki.acl;

import com.example.odysseypki.OdysseyPkiProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.InvalidKeyException;

@Component
public class AclRepository {
    public static final String PRIVATE_KEYS_ACL = "src/main/resources/static/private-keys.acl";

    @Autowired
    private OdysseyPkiProperties properties;

    public void save(String id, String password, String filepath) throws IOException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        var encryptedPassword = AesEncryption.encrypt(password, properties.getSecret());
        var encryptedId = AesEncryption.encrypt(id, properties.getSecret());

        try (BufferedWriter writer = Files.newBufferedWriter(Paths.get(filepath), StandardOpenOption.CREATE, StandardOpenOption.APPEND)) {
            writer.write(encryptedId + "\n");
            writer.write(encryptedPassword + "\n");
        }
    }

    public String load(String id, String filepath) throws IOException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        var encryptedId = AesEncryption.encrypt(id, properties.getSecret());

        try (var reader = Files.newBufferedReader(Paths.get(filepath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.equals(encryptedId)) {
                    line = reader.readLine();
                    if (line == null) throw new IOException("Invalid file format");
                    return AesEncryption.decrypt(line, properties.getSecret());
                }
                reader.readLine();
            }
        }
        return null;
    }
}
