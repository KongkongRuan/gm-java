package com.yxj.gm.provider.key;

import com.yxj.gm.SM2.Key.SM2;

import java.io.Serializable;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;

public class SM2KeyPairGenerator extends KeyPairGeneratorSpi implements Serializable {
    @Override
    public void initialize(int keysize, SecureRandom random) {

    }

    @Override
    public KeyPair generateKeyPair() {
        return SM2.generateSM2KeyPair();
    }
}
