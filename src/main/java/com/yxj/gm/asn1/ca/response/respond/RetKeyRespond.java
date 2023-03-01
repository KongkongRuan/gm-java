package com.yxj.gm.asn1.ca.response.respond;

import com.yxj.gm.asn1.ca.response.respond.envelopeddata.SignedAndEnvelopedData;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

public class RetKeyRespond  extends ASN1Object {

    private ASN1Integer userCertNo;
    private SubjectPublicKeyInfo retPubKey;
    private SignedAndEnvelopedData retPriKey;

    public static RetKeyRespond getInstance(ASN1TaggedObject obj, boolean explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static RetKeyRespond getInstance(Object obj) {
        if (obj instanceof RetKeyRespond) {
            return (RetKeyRespond) obj;
        } else {
            return obj != null ? new RetKeyRespond(ASN1Sequence.getInstance(obj)) : null;
        }
    }

    public RetKeyRespond(ASN1Integer userCertNo,SubjectPublicKeyInfo retPubKey,SignedAndEnvelopedData retPriKey){
        this.userCertNo=userCertNo;
        this.retPubKey=retPubKey;
        this.retPriKey=retPriKey;
    }

    public RetKeyRespond(ASN1Sequence sequence) {
        if (sequence.size() == 3) {
            userCertNo = ASN1Integer.getInstance(sequence.getObjectAt(0));
            retPubKey = SubjectPublicKeyInfo.getInstance(sequence.getObjectAt(1));
            retPriKey = SignedAndEnvelopedData.getInstance(sequence.getObjectAt(2));

        } else {
            throw new IllegalArgumentException("Bad sequence size: " + sequence.size());
        }
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector vec = new ASN1EncodableVector();
        vec.add(userCertNo);
        vec.add(retPubKey);
        vec.add(retPriKey);
        return new DERSequence(vec);
    }
}
