package com.yxj.gm.util;

import com.codahale.shamir.Scheme;
import org.bouncycastle.util.encoders.Hex;

import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

/**
 * shamir门限算法使用DEMO
 *         <dependency>
 *             <groupId>com.codahale</groupId>
 *             <artifactId>shamir</artifactId>
 *             <version>0.7.0</version>
 *         </dependency>
 */
public class ShamirThreshold {


    public static void main(String[] args) {
        SecureRandom secureRandom = new SecureRandom();
        byte[] pubKey = new byte[64];
        secureRandom.nextBytes(pubKey);
        System.out.println("puk:"+Hex.toHexString(pubKey));


         Scheme scheme = new Scheme(secureRandom, 10, 2);

         Map<Integer, byte[]> parts = scheme.split(pubKey);

        Map<Integer, byte[]> test = new HashMap<>();
//        test.put(1,parts.get(1));
//        test.put(2,parts.get(2));
//        test.put(3,parts.get(3));
//        test.put(4,parts.get(4));
//        test.put(5,parts.get(5));
        test.put(10,parts.get(10));
        test.put(9,parts.get(9));

        for (int i = 0; i < parts.size(); i++) {
            System.out.println(Hex.toHexString(parts.get(i+1)));
        }

         byte[] recovered = scheme.join(test);
        System.out.println("rec:"+Hex.toHexString(recovered));
    }
}
