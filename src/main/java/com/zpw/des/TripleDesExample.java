package com.zpw.des;

import com.sun.org.apache.xerces.internal.impl.dv.util.HexBin;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import java.security.SecureRandom;

/**
 * 3重DES加密算法,也叫tripleDES或者DESede
 */
public class TripleDesExample {

    public static void main(String[] args) {
        jdk3des();
    }

    private static void jdk3des(){
        try {
            //生成key
            KeyGenerator keyGenerator = KeyGenerator.getInstance("DESede");
            keyGenerator.init(new SecureRandom());//根据不同算法生成不同的长度
            SecretKey secretKey = keyGenerator.generateKey();
            byte[] encoded = secretKey.getEncoded();//生成密钥key
            //key密钥做转换
            DESedeKeySpec deSedeKeySpec = new DESedeKeySpec(encoded);
            SecretKeyFactory deSede = SecretKeyFactory.getInstance("DESede");
            SecretKey secretKey1 = deSede.generateSecret(deSedeKeySpec);//获取转换后的密钥

            //加密
            Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE,secretKey1);
            byte[] bytes = cipher.doFinal("hello 3des".getBytes());
            System.out.println("加密后的串 :" +  HexBin.encode(bytes));

            //解密
            cipher.init(Cipher.DECRYPT_MODE,secretKey1);
            byte[] bytes1 = cipher.doFinal(bytes);
            System.out.println("解密后的数据:" + new String(bytes1));

        }catch (Exception e){
            e.printStackTrace();
        }
    }

}
