package com.domainizer.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

public class Utils {

    public static TrustManager[] trustAllCerts = new TrustManager[]{
            new X509TrustManager() {
                public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                    return null;
                }

                public void checkClientTrusted(
                        java.security.cert.X509Certificate[] certs, String authType) {
                }

                public void checkServerTrusted(
                        java.security.cert.X509Certificate[] certs, String authType) {
                }
            }
    };
    static Logger log = LoggerFactory.getLogger(Utils.class);

    public static String generateFileName() {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            SecureRandom secureRandom = new SecureRandom();
            byte[] hashByteData = md.digest(secureRandom.generateSeed(128));
            BigInteger hashSigNum = new BigInteger(1, hashByteData);
            StringBuilder hash = new StringBuilder(hashSigNum.toString(16));
            // Add preceding 0s to make it 32 bit
            while (hash.length() < 32) {
                hash.insert(0, "0");
            }
            return hash + ".txt";
        } catch (NoSuchAlgorithmException e) {
            log.error("Error while generating file name");
            log.error(Arrays.toString(e.getStackTrace()));
        }
        return null;
    }

    public static void saveDictionaryFileToDisk(String data, String fileName) {
        String dictionaryDirectory = "dictionaryFiles";
        new File(dictionaryDirectory).mkdirs();
        try {
            File dictionaryFile = new File(dictionaryDirectory + "/" + fileName);
            if (dictionaryFile.createNewFile()) {
                log.info("Dictionary file " + fileName + " created");
                FileWriter fw = new FileWriter(dictionaryFile);
                fw.write(data);
                fw.close();
                log.info("Dictionary file " + fileName + " successfully saved");
            }

        } catch (IOException e) {
            log.error("Error when creating and savind dictionary file to disk");
            log.error(Arrays.toString(e.getStackTrace()));
        }
    }

    public static void generateJwtKey() {
        File key = new File("jwt.key");
        if (!key.exists()) {
            SecureRandom sr = new SecureRandom();
            byte[] byteArray = new byte[2048];
            sr.nextBytes(byteArray);

            try {
                FileOutputStream fos = new FileOutputStream(key);
                fos.write(byteArray);
                fos.close();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }
}
