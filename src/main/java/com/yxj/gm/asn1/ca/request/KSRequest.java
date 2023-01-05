package com.yxj.gm.asn1.ca.request;

import com.yxj.gm.asn1.ca.request.requestList.Request;
import org.bouncycastle.asn1.*;

public class KSRequest extends ASN1Object {
    //默认值V2   V1:0  V2:1  V3:2
    private ASN1Integer version = new ASN1Integer(1);
    private EntName caName;
    private Request requestList;
    private ASN1GeneralizedTime requestTime;
    private ASN1Integer taskNo;

    public static KSRequest getInstance(ASN1TaggedObject obj, boolean explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static KSRequest getInstance(Object obj) {
        if (obj instanceof KSRequest) {
            return (KSRequest) obj;
        } else {
            return obj != null ? new KSRequest(ASN1Sequence.getInstance(obj)) : null;
        }
    }
    public KSRequest(ASN1Sequence sequence) {
        if (sequence.size() == 5) {
            this.version = ASN1Integer.getInstance(sequence.getObjectAt(0));
            this.caName = EntName.getInstance(sequence.getObjectAt(1));
            this.requestList = Request.getInstance(sequence.getObjectAt(2));
            this.requestTime = ASN1GeneralizedTime.getInstance(sequence.getObjectAt(3));
            this.taskNo = ASN1Integer.getInstance(sequence.getObjectAt(4));
        } else {
            throw new IllegalArgumentException("Bad sequence size: " + sequence.size());
        }
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector vec = new ASN1EncodableVector(5);
        vec.add(this.version);
        vec.add(this.caName);
        vec.add(this.requestList);
        vec.add(this.requestTime);
        vec.add(this.taskNo);
        return new DERSequence(vec);
    }
}
