package com.yxj.gm.asn1.ca.request.requestList;

import org.bouncycastle.asn1.*;

public class RequestList extends ASN1Object {
    private Request request;


    public RequestList(Request request){
        this.request=request;
    }

    public static RequestList getInstance(ASN1TaggedObject obj, boolean explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static RequestList getInstance(Object obj) {
        if (obj instanceof RequestList) {
            return (RequestList) obj;
        } else {
            return obj != null ? new RequestList(ASN1Sequence.getInstance(obj)) : null;
        }
    }
    public RequestList(ASN1Sequence sequence) {
        if (sequence.size() == 1) {
            this.request = Request.getInstance(sequence.getObjectAt(0));

        } else {
            throw new IllegalArgumentException("Bad sequence size: " + sequence.size());
        }
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector vec = new ASN1EncodableVector(1);
        vec.add(this.request);
        return new DERSequence(vec);
    }
}
