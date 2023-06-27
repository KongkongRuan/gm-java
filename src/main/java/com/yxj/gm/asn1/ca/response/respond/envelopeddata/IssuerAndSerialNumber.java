package com.yxj.gm.asn1.ca.response.respond.envelopeddata;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.X500Name;

public class IssuerAndSerialNumber extends ASN1Object {
    private X500Name issuer;
    private ASN1Integer serialNumber;

    public IssuerAndSerialNumber(X500Name issuer,ASN1Integer serialNumber) {
        this.issuer=issuer;
        this.serialNumber=serialNumber;
    }

    public static IssuerAndSerialNumber getInstance(ASN1TaggedObject obj, boolean explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static IssuerAndSerialNumber getInstance(Object obj) {
        if (obj instanceof IssuerAndSerialNumber) {
            return (IssuerAndSerialNumber) obj;
        } else {
            return obj != null ? new IssuerAndSerialNumber(ASN1Sequence.getInstance(obj)) : null;
        }
    }
    public IssuerAndSerialNumber(ASN1Sequence sequence) {
        if (sequence.size() == 2) {
            this.issuer = X500Name.getInstance(sequence.getObjectAt(0));
            this.serialNumber = ASN1Integer.getInstance(sequence.getObjectAt(1));
        } else {
            throw new IllegalArgumentException("Bad sequence size: " + sequence.size());
        }
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector vec = new ASN1EncodableVector(5);
        vec.add(this.issuer);
        vec.add(this.serialNumber);
        return new DERSequence(vec);
    }
}
