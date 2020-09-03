package com.zpw.pbe;

import com.sun.org.apache.xerces.internal.impl.dv.util.HexBin;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.security.Key;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * PBE加密算法
 */
public class PbeExample {

    public static void main(String[] args) throws Exception {
        jdkPBE();
    }

    public static void jdkPBE() throws Exception{
        //口令密钥
        String password = "test";
        //转换成密钥
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
        //实例化专程密钥的工厂
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBEWITHMD5andDES");
        Key key = secretKeyFactory.generateSecret(pbeKeySpec);

        //初始化盐，盐就是加密的一些随机数和字符串
        SecureRandom secureRandom = new SecureRandom();
        byte[] salt = secureRandom.generateSeed(8);//产出一个bytes数组

        //加密
        PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt,100);
        Cipher cipher = Cipher.getInstance("PBEWITHMD5andDES");
        cipher.init(Cipher.ENCRYPT_MODE,key,pbeParameterSpec);
        byte[] bytes = cipher.doFinal("hello pbe".getBytes());

        System.out.println("jdk pbe encrypt:" + HexBin.encode(bytes));

        //解密
        cipher.init(Cipher.DECRYPT_MODE,key,pbeParameterSpec);
        byte[] bytes1 = cipher.doFinal(bytes);
        System.out.println("jdk pbe decrypt:" + new String(bytes1));

    }

}
