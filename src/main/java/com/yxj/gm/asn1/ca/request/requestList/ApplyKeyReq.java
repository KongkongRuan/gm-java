package com.yxj.gm.asn1.ca.request.requestList;

import com.yxj.gm.asn1.ca.request.AppUserInfo;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public class ApplyKeyReq extends ASN1Object {
    private AlgorithmIdentifier appKeyType;
    private ASN1Integer appKeyLen;
    private AlgorithmIdentifier retAsymAlg;
    private AlgorithmIdentifier retSymAlg;
    private AlgorithmIdentifier retHashAlg;
    private AppUserInfo appUserInfo;



    public static ApplyKeyReq getInstance(ASN1TaggedObject obj, boolean explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static ApplyKeyReq getInstance(Object obj) {
        if (obj instanceof ApplyKeyReq) {
            return (ApplyKeyReq) obj;
        } else {
            return obj != null ? new ApplyKeyReq(ASN1Sequence.getInstance(obj)) : null;
        }
    }
    public ApplyKeyReq(ASN1Sequence sequence) {
        if (sequence.size() == 6) {
            this.appKeyType = AlgorithmIdentifier.getInstance(sequence.getObjectAt(0));
            this.appKeyLen = ASN1Integer.getInstance(sequence.getObjectAt(1));
            this.retAsymAlg = AlgorithmIdentifier.getInstance(sequence.getObjectAt(2));
            this.retSymAlg = AlgorithmIdentifier.getInstance(sequence.getObjectAt(3));
            this.retHashAlg = AlgorithmIdentifier.getInstance(sequence.getObjectAt(4));
            this.appUserInfo = AppUserInfo.getInstance(sequence.getObjectAt(5));

        } else {
            throw new IllegalArgumentException("Bad sequence size: " + sequence.size());
        }
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector vec = new ASN1EncodableVector(6);
        vec.add(this.appKeyType);
        vec.add(this.appKeyLen);
        vec.add(this.retAsymAlg);
        vec.add(this.retSymAlg);
        vec.add(this.retHashAlg);
        vec.add(this.appUserInfo);
        return new DERSequence(vec);
    }
}
