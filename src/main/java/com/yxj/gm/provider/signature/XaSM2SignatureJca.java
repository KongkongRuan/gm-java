package com.yxj.gm.provider.signature;

import com.yxj.gm.SM2.Signature.SM2Signature;
import com.yxj.gm.provider.algorithmParameterSpec.SM2AlgorithmParameterSpec;

import java.io.Serializable;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

public class XaSM2SignatureJca extends SignatureSpi implements Serializable {

    private PublicKey publicKey;
    private PrivateKey privateKey;

    private byte[] msg;

    private byte[] id;


    /**
     * 验签初始化
     * @param publicKey the public key of the identity whose signature is
     * going to be verified.
     *
     * @throws InvalidKeyException
     */
    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        this.publicKey=publicKey;
    }

    /**
     * 签名初始化
     * @param privateKey the private key of the identity whose signature
     * will be generated.
     *
     * @throws InvalidKeyException
     */
    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        this.privateKey=privateKey;
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {

    }


    /**
     * 预处理
     * @param b the array of bytes
     * @param off the offset to start from in the array of bytes
     * @param len the number of bytes to use, starting at offset
     *
     * @throws SignatureException
     */
    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
        if(id==null){
            id="1234567812345678".getBytes();
        }
        this.msg=b;
    }

    /**
     * 签名
     * @return
     * @throws SignatureException
     */
    @Override
    protected byte[] engineSign() throws SignatureException {
        SM2Signature signature = new SM2Signature();
        if(msg==null)throw new RuntimeException("msg is null ");
        if(privateKey==null)throw new RuntimeException("privateKey is null");
        return signature.signature(msg,id,privateKey.getEncoded());
    }

    /**
     * 验签
     * @param sigBytes the signature bytes to be verified.
     *
     * @return
     * @throws SignatureException
     */
    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        SM2Signature signature = new SM2Signature();
        if(msg==null)throw new RuntimeException("msg is null ");
        if(publicKey==null)throw new RuntimeException("publicKey is null");
        return signature.verify(msg,id,sigBytes,publicKey.getEncoded());
    }

    @Override
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {

    }

    @Override
    protected Object engineGetParameter(String param) throws InvalidParameterException {
        return null;
    }

    @Override
    protected void engineSetParameter(AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException {
        if(params instanceof SM2AlgorithmParameterSpec){
            SM2AlgorithmParameterSpec sm2params = (SM2AlgorithmParameterSpec) params;
            this.id=sm2params.getId();
        }
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        return super.engineGetParameters();
    }
}
