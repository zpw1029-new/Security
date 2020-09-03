package com.zpw.dh;

import com.sun.org.apache.xml.internal.security.utils.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;

/**
 * 非对称，DH算法,密钥交换算法
 * 1.初始化发送方的密钥，然后将公钥发送接收方
 * 2.接收方根据发送方的公钥，生成自己的公钥，私钥，然后公布自己的公钥，发送给发送方
 * 3.接收方根据自己的公钥和自己的私钥生成一个本地密钥
 * 4.发送方根据接收方发送的公钥和自己的私钥，生成一个本地密钥
 * 5.加密
 * 6.解密
 */
public class DHExample {

    public static void main(String[] args) {
        jdkDh();
    }

    public static void jdkDh(){
        try{
            //1.初始化发送方密钥
            KeyPairGenerator sendKeyPairGenerator = KeyPairGenerator.getInstance("DH");
            sendKeyPairGenerator.initialize(512);
            KeyPair sendKeyPair = sendKeyPairGenerator.generateKeyPair();//创建keyPair实例，用于创建密钥对，包括公钥和私钥
            PrivateKey senderPriateKey = sendKeyPair.getPrivate();//保留私钥
            byte[] senderPublicKeyEnc = sendKeyPair.getPublic().getEncoded();//获取公钥,以byte数组为载体,发送给接收方(网络，文件)，公布公钥

            //2.初始化接收方的密钥
            KeyFactory keyFactory = KeyFactory.getInstance("DH");
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(senderPublicKeyEnc);//根据发送方的公钥构建自己的密钥
            PublicKey senderPublicKey = keyFactory.generatePublic(x509EncodedKeySpec);//生成接收方的公钥
            DHParameterSpec dhParameterSpec = ((DHPublicKey) senderPublicKey).getParams();//获取另一方的公钥参数

            KeyPairGenerator receiverKeyPairGenerator = KeyPairGenerator.getInstance("DH");
            receiverKeyPairGenerator.initialize(dhParameterSpec);
            KeyPair receiverKeyPair = receiverKeyPairGenerator.generateKeyPair();
            PrivateKey receiverPrivateKey = receiverKeyPair.getPrivate();//保留自己的私钥
            byte[] receiverPublicKeyEnc = receiverKeyPair.getPublic().getEncoded();//公布接收者公钥

            //生成本地接收方密钥，根据接收方的私钥和发送方的公钥
            KeyFactory senderKeyFactory = KeyFactory.getInstance("DH");
            X509EncodedKeySpec x509EncodedKeySpec1 = new X509EncodedKeySpec(receiverPublicKeyEnc);
            PublicKey receiverPublicKey = senderKeyFactory.generatePublic(x509EncodedKeySpec1);

            KeyAgreement receiverKeyAgreement = KeyAgreement.getInstance("DH");
            receiverKeyAgreement.init(receiverPrivateKey);
            receiverKeyAgreement.doPhase(senderPublicKey,true);
            //根据发送方的公钥生成本地的密钥
            SecretKey receiverDesKey = receiverKeyAgreement.generateSecret("DES");

            //生成发送方的密钥和接收方的公钥
            KeyAgreement senderKeyAgreement = KeyAgreement.getInstance("DH");
            senderKeyAgreement.init(senderPriateKey);
            senderKeyAgreement.doPhase(receiverPublicKey,true);//初始化一个协议
            SecretKey senderDesKey = senderKeyAgreement.generateSecret("DES");

            if (receiverDesKey.equals(senderDesKey)){
                System.out.println("双方密钥相同");
            }

            //4.加密
            Cipher cipher = Cipher.getInstance("DES");
            cipher.init(Cipher.ENCRYPT_MODE,senderDesKey);
            byte[] bytes = cipher.doFinal("hello DH".getBytes());
            System.out.println("jdk dh encyprt : " + Base64.encode(bytes));

            //5.解密
            cipher.init(Cipher.DECRYPT_MODE,receiverDesKey);
            byte[] bytes1 = cipher.doFinal(bytes);
            System.out.println("jdk dh derypt : " + new String(bytes1));

        }catch (Exception e){
            e.printStackTrace();
        }
    }
}
