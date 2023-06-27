package com.yxj.gm.asn1.ca.request;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;

public class EntName  extends ASN1Object {
    private final AlgorithmIdentifier hashAlgorithm;
    private final GeneralName entName;
    private final ASN1OctetString entPubKeyHash;
    private final ASN1Integer serialNumber;
    public EntName(AlgorithmIdentifier hashAlgorithm,GeneralName entName,ASN1OctetString entPubKeyHash,ASN1Integer serialNumber) {
        this.hashAlgorithm=hashAlgorithm;
        this.entName=entName;
        this.entPubKeyHash=entPubKeyHash;
        this.serialNumber=serialNumber;
    }
    public static EntName getInstance(ASN1TaggedObject obj, boolean explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static EntName getInstance(Object obj) {
        if (obj instanceof EntName) {
            return (EntName) obj;
        } else {
            return obj != null ? new EntName(ASN1Sequence.getInstance(obj)) : null;
        }
    }

    public EntName(ASN1Sequence sequence) {

        if(sequence.size()==4) {
            hashAlgorithm = AlgorithmIdentifier.getInstance(sequence.getObjectAt(0));
            entName = GeneralName.getInstance(sequence.getObjectAt(1));
            entPubKeyHash = ASN1OctetString.getInstance(sequence.getObjectAt(2));
            serialNumber=ASN1Integer.getInstance(sequence.getObjectAt(3));
        }else {
            throw new IllegalArgumentException("Bad sequence size: " + sequence.size());
        }
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector vec = new ASN1EncodableVector();
        vec.add(hashAlgorithm);
        vec.add(entName);
        vec.add(entPubKeyHash);
        vec.add(serialNumber);
        return new DERSequence(vec);
    }
}
