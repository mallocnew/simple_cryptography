// Author : fei.hao@mobvoi.com(Fei Hao)
// Date   : Wed Nov 24 14:05:21 CST 2021

package com.mobvoi.cryptography;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class SimpleAES {
    private final static String key = "onegdo80123456wi5zep45v28rkg72vr";
    private final static String iv = "rmbsczv0uohxl67e";

    public static void main(String[] args) throws Exception {
        if (args[0].equals("-e")) {
            byte[] plaintext = GetBytesFromFile(args[1]);
            byte[] ciphertext = AES_Encrypt(plaintext, key, iv);
            WriteBytesToFile("encrypt_file", ciphertext);
        } else if (args[0].equals("-d")) {
            byte[] ciphertext = GetBytesFromFile(args[1]);
            byte[] plaintext = AES_Decrypt(ciphertext, key, iv);
            WriteBytesToFile("decrypt_file", plaintext);
        } else {
            System.out.println("Error!");
        }
    }

    private static byte[] AES_Encrypt(byte[] plaintext, String key, String iv) throws Exception {
        byte[] keyByte = key.getBytes("utf-8");
        SecretKeySpec keyspec = new SecretKeySpec(keyByte, "AES");
        byte[] ivByte = iv.getBytes("utf-8");
        IvParameterSpec ivspec = new IvParameterSpec(ivByte);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keyspec, ivspec);
        byte[] ciphertext = cipher.doFinal(plaintext);
        return ciphertext;
    }

    private static byte[] AES_Decrypt(byte[] ciphertext, String key, String iv) throws Exception {
        byte[] keyByte = key.getBytes("utf-8");
        SecretKeySpec keyspec = new SecretKeySpec(keyByte, "AES");
        byte[] ivByte = iv.getBytes("utf-8");
        IvParameterSpec ivspec = new IvParameterSpec(ivByte);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, keyspec, ivspec);
        byte[] plaintext = cipher.doFinal(ciphertext);
        return plaintext;
    }

    private static byte[] GetBytesFromFile(String filename) throws Exception {
        ByteArrayOutputStream file_data = new ByteArrayOutputStream();
        FileInputStream file = new FileInputStream(filename);
        byte[] buf = new byte[128];
        int len = 0;
        while ((len = file.read(buf)) != -1) {
            file_data.write(buf, 0, len);
        }
        return file_data.toByteArray();
    }

    private static boolean WriteBytesToFile(String filename, byte[] contents) throws Exception {
        ByteArrayInputStream file_data = new ByteArrayInputStream(contents);
        FileOutputStream file = new FileOutputStream(filename);
        byte[] buf = new byte[128];
        int len = 0;
        while ((len = file_data.read(buf, 0, 128)) != -1) {
            file.write(buf, 0, len);
        }
        return true;
    }
}