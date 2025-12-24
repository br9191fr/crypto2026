package com.cecurity;

import java.security.GeneralSecurityException;
import java.security.Security;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;

import javax.crypto.Cipher;

//TIP To <b>Run</b> code, press <shortcut actionId="Run"/> or
// click the <icon src="AllIcons.Actions.Execute"/> icon in the gutter.
public class Main {
    static void main() throws Exception {

        IO.println("Hello and welcome!");

        for (int i = 1; i <= 5; i++) {
            IO.println("i = " + i);
        }
        Security.addProvider(new BouncyCastleFipsProvider());
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding","BCFIPS");
        IO.println("OK Bye");
    }
}
