package org.example;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Cipher;
import java.util.Base64;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.stream.Stream;
import java.io.IOException;
import java.io.BufferedReader;
import java.io.FileReader;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.Security;

public class Main {
    private static String decrypt(String passphrase) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(passphrase.getBytes(), "AES/ECB/PKCS7Padding");
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(2, secretKeySpec);
        // uS0D11dq3RM9QimRWfXcewwQdoxYwrZRNUGT205pDfQ=
        byte[] decode = new byte[] {(byte)185, (byte)45, (byte)3, (byte)215, (byte)87, (byte)106, (byte)221, (byte)19, (byte)61, (byte)66, (byte)41, (byte)145, (byte)89, (byte)245, (byte)220, (byte)123, (byte)12, (byte)16, (byte)118, (byte)140, (byte)88, (byte)194, (byte)182, (byte)81, (byte)53, (byte)65, (byte)147, (byte)219, (byte)78, (byte)105, (byte)13, (byte)244};
        for (int i = 0; i < 313370; i++) {
            decode = cipher.doFinal(decode);
        }
        Cipher cipher2 = Cipher.getInstance("AES/ECB/PKCS7Padding");
        cipher2.init(2, secretKeySpec);
        return new String(cipher2.doFinal(decode), "UTF-8");
    }
    public static void main(String[] args) throws IOException {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        try (BufferedReader reader = new BufferedReader(new FileReader("rockyou.txt"))) {
            for (;;) {
                String line = reader.readLine();
                if(line==null) break;
                if(line.length() != 32) continue;
                try {
                    System.out.println(line + " " + decrypt(line));
                    // INS{H4PPY_H4CK1N6}
                } catch(Exception exc) {
                    //exc.printStackTrace();
                }
            }
        }
    }
}
