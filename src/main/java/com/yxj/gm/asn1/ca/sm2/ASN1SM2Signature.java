package com.yxj.gm.asn1.ca.sm2;

import org.bouncycastle.asn1.*;

public class ASN1SM2Signature extends ASN1Object {
    private ASN1Integer R;
    private ASN1Integer S;
    public ASN1SM2Signature(ASN1Integer R, ASN1Integer S) {
        this.R=R;
        this.S=S;
    }

    public static ASN1SM2Signature getInstance(ASN1TaggedObject obj, boolean explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static ASN1SM2Signature getInstance(Object obj) {
        if (obj instanceof ASN1SM2Signature) {
            return (ASN1SM2Signature) obj;
        } else {
            return obj != null ? new ASN1SM2Signature(ASN1Sequence.getInstance(obj)) : null;
        }
    }
    public ASN1SM2Signature(ASN1Sequence sequence) {
        if (sequence.size() == 2) {
            this.R = ASN1Integer.getInstance(sequence.getObjectAt(0));
            this.S = ASN1Integer.getInstance(sequence.getObjectAt(1));


        } else {
            throw new IllegalArgumentException("Bad sequence size: " + sequence.size());
        }
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector vec = new ASN1EncodableVector(4);
        vec.add(this.R);
        vec.add(this.S);
        return new DERSequence(vec);
    }
    public byte[] toSignatureByteArray(){
        byte[] r = this.R.getPositiveValue().toByteArray();
        byte[] s = this.S.getPositiveValue().toByteArray();
        byte[] signature = new byte[64];
        System.arraycopy(r,0,signature,32-r.length,r.length);
        System.arraycopy(s,0,signature,64-s.length,s.length);
        return signature;
    }

}
