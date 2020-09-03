package com.zpw.rsa;

import com.sun.org.apache.xml.internal.security.utils.Base64;

import javax.crypto.Cipher;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * jdk的rsa算法  基于因子分解
 */
public class RSAExample {
    public static void main(String[] args) {
        jdkRsa();
    }
    public static void jdkRsa(){
        try {

            //1.初始化密钥
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(512);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();//获取生成密钥对的keypair
            //获取RSA的公钥
            RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
            RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();
            System.out.println("Public key:" + com.sun.org.apache.xml.internal.security.utils.Base64.encode(rsaPublicKey.getEncoded()));
            System.out.println("Private key:" + com.sun.org.apache.xml.internal.security.utils.Base64.encode(rsaPrivateKey.getEncoded()));

            //私钥加密，公钥解密 ---- 加密
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(rsaPrivateKey.getEncoded());//私钥的ASN编码
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE,privateKey);
            byte[] bytes = cipher.doFinal("hello rsa".getBytes());
            System.out.println("私钥加密，公钥解密,加密:" + com.sun.org.apache.xml.internal.security.utils.Base64.encode(bytes));

            //私钥加密，公钥解密-----解密
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(rsaPublicKey.getEncoded());//公钥的ASN编码
            keyFactory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
            cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE,publicKey);
            byte[] bytes1 = cipher.doFinal(bytes);
            System.out.println("私钥加密，公钥解密，解密：" + new String(bytes1));

            //公钥加密，私钥解密 -----加密
            x509EncodedKeySpec = new X509EncodedKeySpec(rsaPublicKey.getEncoded());
            keyFactory = KeyFactory.getInstance("RSA");
            publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
            cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE,publicKey);
            byte[] result = cipher.doFinal("hello rsa".getBytes());
            System.out.println("公钥加密，私钥解密 -----加密 ： " + Base64.encode(result));

            //公钥加密，私钥解密----解密
            pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(rsaPrivateKey.getEncoded());
            keyFactory = KeyFactory.getInstance("RSA");
            privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
            cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE,privateKey);
            result = cipher.doFinal(result);
            System.out.println("公钥加密，私钥解密 -----解密：" + new String(result));

        }catch (Exception e){
            e.printStackTrace();
        }
    }
}
