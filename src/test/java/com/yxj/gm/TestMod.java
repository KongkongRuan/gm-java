package com.yxj.gm;

import java.math.BigInteger;

public class TestMod {
    public static void main(String[] args) {
        BigInteger a = new BigInteger("9");
        BigInteger p = new BigInteger("7");
        BigInteger moda = a.mod(p);
        System.out.println(moda.multiply(moda.multiply(moda)).mod(p));
        System.out.println(a.multiply(a.multiply(a)).mod(p));
    }
}
