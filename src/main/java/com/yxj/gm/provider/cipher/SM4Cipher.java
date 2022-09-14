package com.yxj.gm.provider.cipher;

import com.yxj.gm.SM4.SM4;
import com.yxj.gm.enums.PaddingEnum;
import com.yxj.gm.provider.algorithmParameterSpec.SM4AlgorithmParameterSpec;

import javax.crypto.*;
import java.io.Serializable;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

public class SM4Cipher extends CipherSpi implements Serializable {
    private String mode="CTR";
    private String padding="Pkcs7";
    private int cipherMode;

    private byte[] iv;
    private Key key;

    private byte[][] rks;
    SM4 sm4 = new SM4();

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        this.mode=mode;
    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        this.padding=padding;
        if(padding.equals("Pkcs7")){
            sm4.setPadding(PaddingEnum.Pkcs7);
        }else {
            throw new RuntimeException("不支持的填充模式");
        }
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
    protected void engineInit(int i, Key key, SecureRandom secureRandom) throws InvalidKeyException {

        this.cipherMode=i;
        this.key=key;
        //生成轮密钥
        this.rks = sm4.ext_key_L(key.getEncoded());
    }

    @Override
    protected void engineInit(int i, Key key, AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) throws InvalidKeyException, InvalidAlgorithmParameterException {

        this.cipherMode=i;
        this.key=key;
        if(algorithmParameterSpec instanceof SM4AlgorithmParameterSpec){
            SM4AlgorithmParameterSpec spec = (SM4AlgorithmParameterSpec) algorithmParameterSpec;
            this.iv=spec.getIv();
        }
        //生成轮密钥
        this.rks = sm4.ext_key_L(key.getEncoded());
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
    protected byte[] engineDoFinal(byte[] bytes, int i, int i1) throws IllegalBlockSizeException, BadPaddingException {
        if(iv==null){
            iv="1234567812345678".getBytes();
        }
        if(cipherMode==Cipher.ENCRYPT_MODE){
            //加
            byte[] result=null;
            switch (mode){
                case "ECB":
                    result = sm4.blockEncryptECB(bytes,rks);
                    break;
                case "CBC":
                    result = sm4.blockEncryptCBC(bytes,iv,rks);
                    break;
                case "CFB":
                case "OFB":
                    break;
                case "CTR":
                    result= sm4.blockEncryptCTR(bytes,iv,rks);
                    break;
                default:
                    throw new RuntimeException("加密模式错误："+mode);
            }
            return result;
        }else {
            //解密

            byte[] result=null;
            switch (mode){
                case "ECB":
                    result = sm4.blockDecryptECB(bytes,rks);
                    break;
                case "CBC":
                    result = sm4.blockDecryptCBC(bytes,iv,rks);
                    break;
                case "CFB":
                case "OFB":
                    break;
                case "CTR":
                    result= sm4.blockEncryptCTR(bytes,iv,rks);
                    break;
                default:
                    throw new RuntimeException("解密模式错误："+mode);
            }
            return result;
        }

    }

    @Override
    protected int engineDoFinal(byte[] bytes, int i, int i1, byte[] bytes1, int i2) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        return 0;
    }
}
