package com.yxj.gm.asn1.ca.response.respond;

import org.bouncycastle.asn1.*;

public class ErrDesc extends ASN1Object {


    private ASN1UTF8String errDescUTF8;


    public static ErrDesc getInstance(ASN1TaggedObject obj, boolean explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static ErrDesc getInstance(Object obj) {
        if (obj instanceof ErrDesc) {
            return (ErrDesc) obj;
        } else {
            return obj != null ? new ErrDesc(ASN1Sequence.getInstance(obj)) : null;
        }
    }

    public ErrDesc(ASN1UTF8String errDescUTF8){
        this.errDescUTF8=errDescUTF8;
    }

    public ErrDesc(ASN1Sequence sequence) {
        if (sequence.size() == 1) {
            errDescUTF8 = ASN1UTF8String.getInstance(sequence.getObjectAt(0));
        } else {
            throw new IllegalArgumentException("Bad sequence size: " + sequence.size());
        }
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector vec = new ASN1EncodableVector();
        vec.add(errDescUTF8);
        return new DERSequence(vec);
    }
}
