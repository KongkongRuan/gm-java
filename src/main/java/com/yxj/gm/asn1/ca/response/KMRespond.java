package com.yxj.gm.asn1.ca.response;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public class KMRespond extends ASN1Object {
    KSRespond ksRespond;
    AlgorithmIdentifier signatureAlgorithm;
    ASN1OctetString signatureValue;





    public static KMRespond getInstance(ASN1TaggedObject obj, boolean explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static KMRespond getInstance(Object obj) {
        if (obj instanceof KMRespond) {
            return (KMRespond) obj;
        } else {
            return obj != null ? new KMRespond(ASN1Sequence.getInstance(obj)) : null;
        }
    }

    public KMRespond(ASN1Sequence sequence) {
        if (sequence.size() == 3) {
            ksRespond = KSRespond.getInstance(sequence.getObjectAt(0));
            signatureAlgorithm = AlgorithmIdentifier.getInstance(sequence.getObjectAt(1));
            signatureValue = ASN1OctetString.getInstance(sequence.getObjectAt(2));

        } else {
            throw new IllegalArgumentException("Bad sequence size: " + sequence.size());
        }
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector vec = new ASN1EncodableVector();
        vec.add(ksRespond);
        vec.add(signatureAlgorithm);
        vec.add(signatureValue);

        return new DERSequence(vec);
    }
}
