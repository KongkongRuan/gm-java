package com.yxj.gm.asn1.ca.request;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public class CARequest extends ASN1Object {
    private KSRequest ksRequest;
    private AlgorithmIdentifier algorithmIdentifier;
    private ASN1OctetString signatureValue;

    public static CARequest getInstance(ASN1TaggedObject obj, boolean explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static CARequest getInstance(Object obj) {
        if (obj instanceof CARequest) {
            return (CARequest) obj;
        } else {
            return obj != null ? new CARequest(ASN1Sequence.getInstance(obj)) : null;
        }
    }
    public CARequest(ASN1Sequence sequence) {
        if (sequence.size() == 3) {
            this.ksRequest = KSRequest.getInstance(sequence.getObjectAt(0));
            this.algorithmIdentifier = AlgorithmIdentifier.getInstance(sequence.getObjectAt(1));
            this.signatureValue = ASN1OctetString.getInstance(sequence.getObjectAt(2));

        } else {
            throw new IllegalArgumentException("Bad sequence size: " + sequence.size());
        }
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector vec = new ASN1EncodableVector(3);
        vec.add(this.ksRequest);
        vec.add(this.algorithmIdentifier);
        vec.add(this.signatureValue);
        return new DERSequence(vec);
    }
}
