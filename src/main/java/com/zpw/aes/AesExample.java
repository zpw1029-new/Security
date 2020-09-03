package com.zpw.aes;

import com.sun.org.apache.xerces.internal.impl.dv.util.HexBin;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.SecureRandom;
import java.security.Security;

/**
 * AES对称加密算法
 */
public class AesExample {
    private static String src = "hello aes";

    public static void main(String[] args) {
        jdkAes();
        bcAes();
    }

    public static void jdkAes(){
        try {
            //生成key
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(new SecureRandom());
            SecretKey secretKey = keyGenerator.generateKey();
            byte[] keyBytes = secretKey.getEncoded();

            //key的转换
            Key key = new SecretKeySpec(keyBytes,"AES");

            //加密
            Cipher instance = Cipher.getInstance("AES/ECB/PKCS5Padding");
            instance.init(Cipher.ENCRYPT_MODE,key);
            byte[] bytes = instance.doFinal(src.getBytes());
            System.out.println("加密后的结果:" + HexBin.encode(bytes));

            //解密
            instance.init(Cipher.DECRYPT_MODE,key);
            byte[] bytes1 = instance.doFinal(bytes);
            System.out.println("解密后的结果：" + new String(bytes1));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void bcAes(){
        try {
            Security.addProvider(new BouncyCastleProvider());
            //生成key
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES","BC");
            keyGenerator.init(128);
            System.out.println(keyGenerator.getProvider());
            SecretKey secretKey = keyGenerator.generateKey();
            byte[] keyBytes = secretKey.getEncoded();

            //key的转换
            Key key = new SecretKeySpec(keyBytes,"AES");

            //加密
            Cipher instance = Cipher.getInstance("AES/ECB/PKCS5Padding");
            instance.init(Cipher.ENCRYPT_MODE,key);
            byte[] bytes = instance.doFinal(src.getBytes());
            System.out.println("加密后的结果:" + HexBin.encode(bytes));

            //解密
            instance.init(Cipher.DECRYPT_MODE,key);
            byte[] bytes1 = instance.doFinal(bytes);
            System.out.println("解密后的结果：" + new String(bytes1));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
