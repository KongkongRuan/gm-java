package com.yxj.gm.asn1.ca.response;

import com.yxj.gm.asn1.ca.request.EntName;
import com.yxj.gm.asn1.ca.response.respond.Respond;
import org.bouncycastle.asn1.*;

import java.math.BigInteger;

public class KSRespond  extends ASN1Object {
    ASN1Integer version;
    EntName kmName;
    Respond respondList;
    ASN1GeneralizedTime respondTime;
    ASN1Integer taskNo;
    public KSRespond(EntName kmName,Respond respondList,ASN1GeneralizedTime respondTime,ASN1Integer taskNo) {
        this.version=new ASN1Integer(new BigInteger("1"));
        this.kmName=kmName;
        this.respondList=respondList;
        this.respondTime=respondTime;
        this.taskNo=taskNo;
    }

    public static KSRespond getInstance(ASN1TaggedObject obj, boolean explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static KSRespond getInstance(Object obj) {
        if (obj instanceof KSRespond) {
            return (KSRespond) obj;
        } else {
            return obj != null ? new KSRespond(ASN1Sequence.getInstance(obj)) : null;
        }
    }

    public KSRespond(ASN1Sequence sequence) {
        if (sequence.size() == 5) {
            version = ASN1Integer.getInstance(sequence.getObjectAt(0));
            kmName = EntName.getInstance(sequence.getObjectAt(1));
            respondList = Respond.getInstance(sequence.getObjectAt(2));
            respondTime = ASN1GeneralizedTime.getInstance(sequence.getObjectAt(3));
            taskNo = ASN1Integer.getInstance(sequence.getObjectAt(4));

        } else {
            throw new IllegalArgumentException("Bad sequence size: " + sequence.size());
        }
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector vec = new ASN1EncodableVector();
        vec.add(version);
        vec.add(kmName);
        vec.add(new DERSequence(respondList));
        vec.add(respondTime);
        vec.add(taskNo);
        return new DERSequence(vec);
    }
}
