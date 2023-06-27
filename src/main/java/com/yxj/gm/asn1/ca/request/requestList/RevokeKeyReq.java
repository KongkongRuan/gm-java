package com.yxj.gm.asn1.ca.request.requestList;

import org.bouncycastle.asn1.*;

public class RevokeKeyReq  extends ASN1Object {

    private ASN1Integer userCertNo;
    public static final int tagNo = 2;

    public static RevokeKeyReq getInstance(ASN1TaggedObject obj, boolean explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static RevokeKeyReq getInstance(Object obj) {
        if (obj instanceof RevokeKeyReq) {
            return (RevokeKeyReq) obj;
        } else {
            return obj != null ? new RevokeKeyReq(ASN1Sequence.getInstance(obj)) : null;
        }
    }
    public RevokeKeyReq(ASN1Sequence sequence) {
        if (sequence.size() == 1) {
            this.userCertNo = ASN1Integer.getInstance(sequence.getObjectAt(0));
        } else {
            throw new IllegalArgumentException("Bad sequence size: " + sequence.size());
        }
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector vec = new ASN1EncodableVector(1);
        vec.add(this.userCertNo);
        return new DERSequence(vec);
    }
}
