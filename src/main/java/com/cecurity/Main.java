package com.cecurity;


import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.Enumeration;
import java.util.zip.ZipEntry;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.*;


import org.bouncycastle.jcajce.spec.AEADParameterSpec;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

public class Main {
    static void main() {

        Security.addProvider(new BouncyCastleFipsProvider("C:HYBRID;ENABLE{ALL};"));
        Security.addProvider(new BouncyCastleJsseProvider("fips:BCFIPS"));
        try {
            test2();
            test_gcm_256(false);
            test_gcm_256(true);
            test_tls1();
            writeToFileZipFileContents("test.zip", "output.txt");
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
        int len_in = pText.length;
        byte[] out = cipher.doFinal(pText);
        int len_out = out.length;
        System.out.println("len_in = " + len_in + ", len_out = " + len_out);
        return out ;
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


    static void test_gcm_256(boolean withError) throws Exception {
        try {
            if (withError) {
                IO.println("\ntest_gcm_256 running with error\n----");
            }
            else {
                IO.println("\ntest_gcm_256 running without error\n----");
            }
            Cipher _ = Cipher.getInstance("AES/CBC/PKCS5Padding", "BCFIPS");
            KeyGenerator keyGen = KeyGenerator.getInstance("AES", "BCFIPS");
            keyGen.init(256);
            SecretKey aesKey = keyGen.generateKey();
            IO.println("AES Key :"+ Hex.toHexString(aesKey.getEncoded())+" Len:"+aesKey.getEncoded().length);
            /*
            saving AES key
             */
            String saveKey = Hex.toHexString(aesKey.getEncoded());
            byte[] data = Hex.decode("000102030405060708090A0B0C0D0E0F1011121314151617181910111213141516171819");
            byte[] assocData = Hex.decode("1011121314151617181910111213141516171891");
            byte[] nonce = Hex.decode("202122232425262728292a2b2c");
            Cipher enc = Cipher.getInstance("AES/GCM/NoPadding", "BCFIPS");
            System.out.println("oText: " + Hex.toHexString(data));
            int len_in = data.length;

            enc.init(Cipher.ENCRYPT_MODE, aesKey,
                    new AEADParameterSpec(nonce, 96, assocData));
            byte[] encrypted = enc.doFinal(data);
            int len_out = encrypted.length;
            System.out.println("len_in = " + len_in + ", len_out = " + len_out);
            // create Error here
            if (withError) {
                encrypted[0] = (byte) ~encrypted[0];
            }
            System.out.println("cText: " + Hex.toHexString(encrypted));
            Cipher dec = Cipher.getInstance("AES/GCM/NoPadding", "BCFIPS");
            /*
             Restore saved AES key
             */
            SecretKey savedKey2 = new SecretKeySpec(Hex.decode(saveKey), "AES");
            dec.init(Cipher.DECRYPT_MODE, savedKey2, new AEADParameterSpec(nonce, 96, assocData));
            int len_dec = dec.getOutputSize(len_out);
            IO.println("len_dec = " + len_dec);
            byte[] decBuf = new byte[len_dec];
            int len_final = dec.update(encrypted, 0, encrypted.length, decBuf, 0);
            IO.println("len_final = " + len_final);
            len_final += dec.doFinal(decBuf, len_final);
            IO.println("len_final = " + len_final);
            IO.println("dText: " + Hex.toHexString(decBuf, 0, len_final));
        } catch (Exception e) {
            IO.println("----------------------------\nIn test1: Exception: " + e.getMessage());
            IO.println("----------------------------");
            //e.printStackTrace();
            //throw e;
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
    public static void writeToFileZipFileContents(String zipFileName,
                                                  String outputFileName)
            throws java.io.IOException {

        java.nio.charset.Charset charset =
                java.nio.charset.StandardCharsets.US_ASCII;
        java.nio.file.Path outputFilePath =
                java.nio.file.Paths.get(outputFileName);

        // Open zip file and create output file with
        // try-with-resources statement
        IO.println("\n\nIn writeToFileZipFileContents: zipFileName = " + zipFileName);
        IO.println("Reading zip file:"+java.nio.file.Paths.get(zipFileName));
        try (
                java.util.zip.ZipFile zf =
                        new java.util.zip.ZipFile(zipFileName);
                java.io.BufferedWriter writer =
                        java.nio.file.Files.newBufferedWriter(outputFilePath, charset)
        ) {
            // Enumerate each entry
            IO.println("Enter loop");
            int count = 0;
            Enumeration<? extends ZipEntry> entries;
            for (entries = zf.entries(); entries.hasMoreElements();) {
                // Get the entry name and write it to the output file
                String newLine;
                newLine = System.lineSeparator();
                String zipEntryName;
                zipEntryName = new StringBuilder().append(entries.nextElement().getName()).append(newLine).toString();
                //IO.println("zipEntryName = " + zipEntryName);
                writer.write(zipEntryName, 0, zipEntryName.length());
                count++;
            }
            IO.println("Found "+count+" entries");
        }
        IO.println("End of writeToFileZipFileContents: zipFileName");
    }
}
