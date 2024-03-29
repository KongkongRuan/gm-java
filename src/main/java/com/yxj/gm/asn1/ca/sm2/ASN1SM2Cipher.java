package com.yxj.gm.asn1.ca.sm2;

import org.bouncycastle.asn1.*;

public class ASN1SM2Cipher extends ASN1Object {
    private ASN1Integer x;
    private ASN1Integer y;
    private ASN1OctetString hash;
    private ASN1OctetString cipherText;

    public ASN1Integer getX() {
        return x;
    }

    public ASN1Integer getY() {
        return y;
    }

    public ASN1OctetString getHash() {
        return hash;
    }

    public ASN1OctetString getCipherText() {
        return cipherText;
    }

    public static ASN1SM2Cipher getInstance(ASN1TaggedObject obj, boolean explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }
    public byte[] sm2CipherToByte(){
        byte[] xBytes = this.x.getPositiveValue().toByteArray();
        byte[] yBytes = this.y.getPositiveValue().toByteArray();
        byte[] hashBytes = this.hash.getOctets();
        byte[] cipherTextBytes = this.cipherText.getOctets();
        byte[] result = new byte[xBytes.length + yBytes.length + hashBytes.length + cipherTextBytes.length];
        System.arraycopy(xBytes, 0, result, 0, xBytes.length);
        System.arraycopy(yBytes, 0, result, xBytes.length, yBytes.length);
        System.arraycopy(hashBytes, 0, result, xBytes.length + yBytes.length, hashBytes.length);
        System.arraycopy(cipherTextBytes, 0, result, xBytes.length + yBytes.length + hashBytes.length, cipherTextBytes.length);
        return result;
    }
    public static ASN1SM2Cipher getInstance(Object obj) {
        if (obj instanceof ASN1SM2Cipher) {
            return (ASN1SM2Cipher) obj;
        } else {
            return obj != null ? new ASN1SM2Cipher(ASN1Sequence.getInstance(obj)) : null;
        }
    }
    public ASN1SM2Cipher(ASN1Integer x,ASN1Integer y,ASN1OctetString hash,ASN1OctetString cipherText){
        this.x=x;
        this.y=y;
        this.hash=hash;
        this.cipherText=cipherText;
    }
    public ASN1SM2Cipher(ASN1Sequence sequence) {
        if (sequence.size() == 4) {
            this.x = ASN1Integer.getInstance(sequence.getObjectAt(0));
            this.y = ASN1Integer.getInstance(sequence.getObjectAt(1));
            this.hash = ASN1OctetString.getInstance(sequence.getObjectAt(2));
            this.cipherText = ASN1OctetString.getInstance(sequence.getObjectAt(3));

        } else {
            throw new IllegalArgumentException("Bad sequence size: " + sequence.size());
        }
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector vec = new ASN1EncodableVector(4);
        vec.add(this.x);
        vec.add(this.y);
        vec.add(this.hash);
        vec.add(this.cipherText);
        return new DERSequence(vec);
    }
}
