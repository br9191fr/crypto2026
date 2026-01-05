package com.cecurity;


import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.Certificate;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.*;


import org.bouncycastle.jcajce.spec.AEADParameterSpec;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

//TIP To <b>Run</b> code, press <shortcut actionId="Run"/> or
// click the <icon src="AllIcons.Actions.Execute"/> icon in the gutter.
public class Main {
    static void main() {

        IO.println("Hello and welcome!");

        for (int i = 1; i <= 5; i++) {
            IO.println("i = " + i);
        }
        Security.addProvider(new BouncyCastleFipsProvider("C:HYBRID;ENABLE{ALL};"));
        Security.addProvider(new BouncyCastleJsseProvider("fips:BCFIPS"));
        try {
            test1();
            test2();
            test_tls1();
        } catch (Exception e) {
            //e.printStackTrace();
            System.out.println("In main: Exception: " + e.getMessage());
        } finally {
            IO.println("OK Bye");
        }
    }

    @org.jetbrains.annotations.NotNull
    @org.jetbrains.annotations.Contract(" -> new")
    static SecretKey createConstantKey() {
        return new SecretKeySpec(
                Hex.decode("000102030405060708090a0b0c0d0e0f"), "AES");
    }

    /**
     * Encrypt the passed in data pText using GCM with the passed in parameters
     * and incorporating aData into the GCM MAC calculation.
     *
     * @param key   secret key to use.
     * @param iv    the IV to use with GCM.
     * @param pText the plain text input to the cipher.
     * @param aData the associated data to be included in the GCM MAC.
     * @return the cipher text.
     *
     */
    static byte[] gcmEncryptWithAAD(SecretKey key,
                                    byte[] iv,
                                    byte[] pText,
                                    byte[] aData)
            throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BCFIPS");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        cipher.updateAAD(aData);
        return cipher.doFinal(pText);
    }

    /**
     * Decrypt the passed in cipher text cText using GCM with the passed in
     * parameters and incorporating aData into the GCM MAC calculation.
     *
     * @param key   secret key to use.
     * @param iv    the IV originally used with GCM.
     * @param cText the encrypted cipher text.
     * @param aData the associated data to be included in the GCM MAC.
     * @return the plain text.
     */
    static byte[] gcmDecryptWithAAD(SecretKey key,
                                    byte[] iv,
                                    byte[] cText,
                                    byte[] aData)
            throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BCFIPS");
        AEADParameterSpec spec = new AEADParameterSpec(iv, 128, aData);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);
        return cipher.doFinal(cText);
    }


    static void test1() throws Exception {
        try {
            IO.println("test1 start");
            Cipher _ = Cipher.getInstance("AES/CBC/PKCS5Padding", "BCFIPS");
            KeyGenerator keyGen = KeyGenerator.getInstance("AES", "BCFIPS");
            keyGen.init(256);
            SecretKey aesKey = keyGen.generateKey();
            byte[] data = Hex.decode("000102030405060708090A0B0C0D0E0F");
            byte[] assocData = Hex.decode("10111213141516171819");
            byte[] nonce = Hex.decode("202122232425262728292a2b2c");
            Cipher enc = Cipher.getInstance("AES/GCM/NoPadding", "BCFIPS");
            System.out.println("oText: " + Hex.toHexString(data));
            enc.init(Cipher.ENCRYPT_MODE, aesKey,
                    new AEADParameterSpec(nonce, 96, assocData));
            byte[] encrypted = enc.doFinal(data);
            // create Error here
            // encrypted[0] = (byte) ~encrypted[0];
            System.out.println("cText: " + Hex.toHexString(encrypted));
            Cipher dec = Cipher.getInstance("AES/GCM/NoPadding", "BCFIPS");
            dec.init(Cipher.DECRYPT_MODE, aesKey,
                    new AEADParameterSpec(nonce, 96, assocData));
            byte[] plain = dec.doFinal(encrypted);
            System.out.println("dText: " + Hex.toHexString(plain));
        } catch (Exception e) {
            System.out.println("In test1: Exception: " + e.getMessage());
            //e.printStackTrace();
            throw e;
        }
        IO.println("test1 stop");
    }

    static void test2() throws Exception {
        IO.println("test2 start");
        SecretKey aesKey = createConstantKey();
        byte[] iv = Hex.decode("bbaa99887766554433221100");
        String data = "hello, world!";
        byte[] msg = Strings.toByteArray(data);
        byte[] aad = Strings.toByteArray("now is the time!");
        byte[] enc = gcmEncryptWithAAD(aesKey, iv, msg, aad);
        byte[] dec = gcmDecryptWithAAD(aesKey, iv, enc, aad);
        System.out.println("data: " + data);
        System.out.println("enc:  " + Hex.toHexString(enc));
        System.out.println("dec:  " + new String(dec));
        IO.println("test2 stop");
    }


    static void test_tls1() throws Exception {
        IO.println("test_tls1 start");
        PrivateCredential cred = PrivateCredential.createSelfSignedCredentials();

        KeyStore store = KeyStore.getInstance("JKS");

        store.load(null, null);

        store.setKeyEntry("key", cred.getPrivateKey(), "keyPass".toCharArray(),
                new Certificate[]{cred.getCertificate()});
        System.out.println("store created");
        FileOutputStream fOut = new FileOutputStream("basic.jks");

        store.store(fOut, "storePass".toCharArray());
        System.out.println("store saved");
        fOut.close();
        IO.println("test_tls1 stop");
    }
}
