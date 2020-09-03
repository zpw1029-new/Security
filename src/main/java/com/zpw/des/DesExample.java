package com.zpw.des;

import com.sun.org.apache.xerces.internal.impl.dv.util.HexBin;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import java.security.Key;
import java.security.Security;

/**
 * 使用des对称加密
 */
public class DesExample {

    private static String src = "hello world";

    public static void main(String[] args) {
        jdkDes();
        bcDes();
    }

    private static void jdkDes(){
        try {
            //1.生成key
            KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");
            keyGenerator.init(56);//定义key的长度
            SecretKey secretKey = keyGenerator.generateKey();//获取密钥
            byte[] bytes = secretKey.getEncoded();//构建密钥

            //2.key做转换 公布密钥
            DESKeySpec desKeySpec = new DESKeySpec(bytes);
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("DES");//获取生成des的工厂
            Key convertKey = secretKeyFactory.generateSecret(desKeySpec);//获取转化后的生成的密钥

            //3.加密  DES:算法，ECB：工作方式,PKCS5Padding:填充方式
            Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE,convertKey);
            byte[] bytes1 = cipher.doFinal(src.getBytes());
            System.out.println("jdk des encrypt : " + HexBin.encode(bytes1));

            //4 解密
            cipher.init(Cipher.DECRYPT_MODE,convertKey);
            byte[] bytes2 = cipher.doFinal(bytes1);
            System.out.println("jdk des decrypt : " + new String(bytes2));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void bcDes(){
        try {
            //添加bc的provider,是一种用于 Java 平台的开放源码的轻量级密码术包。它支持大量的密码术算法
            //如果需要用其他的算法，就需要引入bouncycastle进行处理
            Security.addProvider(new BouncyCastleProvider());
            //1.生成key
            KeyGenerator keyGenerator = KeyGenerator.getInstance("DES","BC");
            keyGenerator.init(56);//定义key的长度
            keyGenerator.getProvider();
            System.out.println(keyGenerator.getProvider());
            SecretKey secretKey = keyGenerator.generateKey();//获取密钥
            byte[] bytes = secretKey.getEncoded();//构建密钥

            //2.key做转换 公布密钥
            DESKeySpec desKeySpec = new DESKeySpec(bytes);
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("DES");//获取生成des的工厂
            Key convertKey = secretKeyFactory.generateSecret(desKeySpec);//获取转化后的生成的密钥

            //3.加密  DES:算法，ECB：工作方式,PKCS5Padding:填充方式
            Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE,convertKey);
            byte[] bytes1 = cipher.doFinal(src.getBytes());
            System.out.println("bc des encrypt : " + HexBin.encode(bytes1));

            //4 解密
            cipher.init(Cipher.DECRYPT_MODE,convertKey);
            byte[] bytes2 = cipher.doFinal(bytes1);
            System.out.println("bc des decrypt : " + new String(bytes2));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
