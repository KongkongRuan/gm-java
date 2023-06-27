package com.yxj.gm.provider.cipher;

import com.yxj.gm.SM2.Cipher.SM2Cipher;

import javax.crypto.*;
import java.io.Serializable;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

public class XaSM2Cipher extends CipherSpi implements Serializable {
    private int MODE;

    private Key key;

    @Override
    protected void engineInit(int MODE, Key key, SecureRandom secureRandom) throws InvalidKeyException {
        this.MODE=MODE;
        this.key=key;
    }
    @Override
    protected byte[] engineDoFinal(byte[] bytes, int inputOffset, int length) throws IllegalBlockSizeException, BadPaddingException {
        SM2Cipher cipher = new com.yxj.gm.SM2.Cipher.SM2Cipher();
        if(MODE==Cipher.ENCRYPT_MODE){
            //加密
            return cipher.SM2CipherEncrypt(bytes,key.getEncoded());
        }else if(MODE==Cipher.DECRYPT_MODE) {
            //解密
            return cipher.SM2CipherDecrypt(bytes,key.getEncoded());
        }else {
            throw new RuntimeException("SM2 Cipher MODE Error");
        }
    }

    @Override
    protected void engineSetMode(String s) throws NoSuchAlgorithmException {

    }

    @Override
    protected void engineSetPadding(String s) throws NoSuchPaddingException {

    }

    @Override
    protected int engineGetBlockSize() {
        return 0;
    }

    @Override
    protected int engineGetOutputSize(int i) {
        return 0;
    }

    @Override
    protected byte[] engineGetIV() {
        return new byte[0];
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }


    @Override
    protected void engineInit(int i, Key key, AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) throws InvalidKeyException, InvalidAlgorithmParameterException {

    }

    @Override
    protected void engineInit(int i, Key key, AlgorithmParameters algorithmParameters, SecureRandom secureRandom) throws InvalidKeyException, InvalidAlgorithmParameterException {

    }

    @Override
    protected byte[] engineUpdate(byte[] bytes, int i, int i1) {
        return new byte[0];
    }

    @Override
    protected int engineUpdate(byte[] bytes, int i, int i1, byte[] bytes1, int i2) throws ShortBufferException {
        return 0;
    }



    @Override
    protected int engineDoFinal(byte[] bytes, int i, int i1, byte[] bytes1, int i2) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        return 0;
    }
}
