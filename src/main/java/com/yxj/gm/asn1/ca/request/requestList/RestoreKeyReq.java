package com.yxj.gm.asn1.ca.request.requestList;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

public class RestoreKeyReq extends ASN1Object {
    private AlgorithmIdentifier retAsymAlg;
    private AlgorithmIdentifier retSymAlg;
    private AlgorithmIdentifier retHashAlg;
    private ASN1Integer userCertNo;

    private SubjectPublicKeyInfo userPubKey;

    public static RestoreKeyReq getInstance(ASN1TaggedObject obj, boolean explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static RestoreKeyReq getInstance(Object obj) {
        if (obj instanceof RestoreKeyReq) {
            return (RestoreKeyReq) obj;
        } else {
            return obj != null ? new RestoreKeyReq(ASN1Sequence.getInstance(obj)) : null;
        }
    }
    public RestoreKeyReq(ASN1Sequence sequence) {
        if (sequence.size() == 5) {

            this.retAsymAlg = AlgorithmIdentifier.getInstance(sequence.getObjectAt(0));
            this.retSymAlg = AlgorithmIdentifier.getInstance(sequence.getObjectAt(1));
            this.retHashAlg = AlgorithmIdentifier.getInstance(sequence.getObjectAt(2));
            this.userCertNo = ASN1Integer.getInstance(sequence.getObjectAt(3));
            this.userPubKey = SubjectPublicKeyInfo.getInstance(sequence.getObjectAt(4));
        } else {
            throw new IllegalArgumentException("Bad sequence size: " + sequence.size());
        }
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector vec = new ASN1EncodableVector(5);

        vec.add(this.retAsymAlg);
        vec.add(this.retSymAlg);
        vec.add(this.retHashAlg);
        vec.add(this.userCertNo);
        vec.add(this.userPubKey);
        return new DERSequence(vec);
    }
}
