package com.yxj.gm.asn1.ca.response.respond;

import org.bouncycastle.asn1.*;

public class RevokekeyRespond extends ASN1Object {
    private ASN1Integer userCertNo;

    public static RevokekeyRespond getInstance(ASN1TaggedObject obj, boolean explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static RevokekeyRespond getInstance(Object obj) {
        if (obj instanceof RevokekeyRespond) {
            return (RevokekeyRespond) obj;
        } else {
            return obj != null ? new RevokekeyRespond(ASN1Sequence.getInstance(obj)) : null;
        }
    }

    public RevokekeyRespond(ASN1Sequence sequence) {
        if (sequence.size() == 1) {
            userCertNo = ASN1Integer.getInstance(sequence.getObjectAt(0));

        } else {
            throw new IllegalArgumentException("Bad sequence size: " + sequence.size());
        }
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector vec = new ASN1EncodableVector();
        vec.add(userCertNo);

        return new DERSequence(vec);
    }
}
