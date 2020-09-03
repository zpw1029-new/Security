package com.zpw.elgamal;

import com.sun.org.apache.xml.internal.security.utils.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.spec.DHParameterSpec;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * elgamal算法，基于离散数学
 */
public class ElgamalExample {
    public static void main(String[] args) {
        bcElgamal();
    }

    private static void bcElgamal() {

        try {
            //1.添加bc，集成算法 在使用之前需要为JDK添加新的Provider
            Security.addProvider(new BouncyCastleProvider());

            //2.公钥加密，私钥解密
            //初始化密钥
            AlgorithmParameterGenerator algorithmParameterGenerator = AlgorithmParameterGenerator.getInstance("Elgamal");
            algorithmParameterGenerator.init(256);
            // 生成算法参数
            AlgorithmParameters algorithmParameters = algorithmParameterGenerator.generateParameters();
            // 构建参数材料
            // JDK没有提供对ei的支持，但是jce框架提供了构建秘钥对的方式DHParameterSpec
            DHParameterSpec dhParameterSpec = (DHParameterSpec)algorithmParameters.getParameterSpec(DHParameterSpec.class);

            //生成密钥对 实例化密钥对生成器
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("Elgamal");
            keyPairGenerator.initialize(dhParameterSpec,new SecureRandom());
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            //生成公钥和密钥
            PublicKey aPublic = keyPair.getPublic();
            PrivateKey aPrivate = keyPair.getPrivate();
            System.out.println("Public key :" + Base64.encode(aPublic.getEncoded()));
            System.out.println("Private key : " + Base64.encode(aPrivate.getEncoded()));

            //初始化公钥，并作密钥转换
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(aPublic.getEncoded());
            KeyFactory keyFactory = KeyFactory.getInstance("Elgamal");
            PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);

            //加密
            Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
            cipher.init(Cipher.ENCRYPT_MODE,publicKey);
            byte[] result = cipher.doFinal("hello elagamal".getBytes());
            System.out.println("公钥加密，私钥解密,加密:" + Base64.encode(result));

            //解密
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(aPrivate.getEncoded());//私钥的ASN编码
            keyFactory = KeyFactory.getInstance("Elgamal");
            PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
            cipher = Cipher.getInstance(keyFactory.getAlgorithm());
            cipher.init(Cipher.DECRYPT_MODE,privateKey);
            result = cipher.doFinal(result);
            System.out.println("公钥加密，私钥解密，解密:" + new String(result));


        }catch (Exception e){
            e.printStackTrace();
        }


    }
}
