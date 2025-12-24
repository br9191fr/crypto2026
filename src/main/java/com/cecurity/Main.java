package com.cecurity;

import java.security.GeneralSecurityException;
import java.security.Security;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.*;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jcajce.spec.AEADParameterSpec;
import org.bouncycastle.util.encoders.Hex;

//TIP To <b>Run</b> code, press <shortcut actionId="Run"/> or
// click the <icon src="AllIcons.Actions.Execute"/> icon in the gutter.
public class Main {
    static void main() throws Exception {

        IO.println("Hello and welcome!");

        for (int i = 1; i <= 5; i++) {
            IO.println("i = " + i);
        }
        Security.addProvider(new BouncyCastleFipsProvider("C:HYBRID;ENABLE{ALL};"));
        try {
            test1();
        } catch (Exception e) {
            //e.printStackTrace();
            System.out.println("In main: Exception: " + e.getMessage());
        }
        finally {
            IO.println("OK Bye");
        }
    }
    static void test1() throws Exception {
        try {
            Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding", "BCFIPS");
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
        }
        catch (Exception e) {
            System.out.println("In test1: Exception: " + e.getMessage());
            //e.printStackTrace();
            throw e;
        }
    }
}
