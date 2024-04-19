package com.example.odysseypki.repository;

import com.example.odysseypki.OdysseyPkiProperties;
import com.example.odysseypki.algorithm.AesEncryption;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

@Component
public class AclRepository {
    public static final String KS_ACL = "src/main/resources/static/ks.acl";
    public static final String PK_ACL = "src/main/resources/static/pk.acl";

    @Autowired
    private OdysseyPkiProperties properties;

    public void save(String id, String password, String filepath) throws IOException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        var encryptedPassword = AesEncryption.encrypt(password, properties.getSecret());
        var encryptedId = AesEncryption.encrypt(id, properties.getSecret());

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(filepath, true))) {
            writer.write(encryptedId + "\n");
            writer.write(encryptedPassword + "\n");
        }
    }

    public String load(String id, String filepath) throws IOException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        var encryptedId = AesEncryption.encrypt(id, properties.getSecret());

        try (BufferedReader reader = new BufferedReader(new FileReader(filepath))) {
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
