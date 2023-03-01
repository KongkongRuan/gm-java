package com.yxj.gm.asn1.ca.response.respond.envelopeddata;


import com.yxj.gm.asn1.ca.sm2.ASN1SM2Cipher;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;

public class RecipientInfo extends ASN1Object {
    //默认值V2   V1:0  V2:1  V3:2
    private ASN1Integer version;
    private IssuerAndSerialNumber issuerAndserialNumber;
    private AlgorithmIdentifier keyEncryptionAlgorithmIdentifier;
    private ASN1SM2Cipher encryptedKey;

    public static RecipientInfo getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static RecipientInfo getInstance(Object obj) {
        if (obj instanceof RecipientInfo) {
            return (RecipientInfo) obj;
        } else {
            return obj != null ? new RecipientInfo(ASN1Sequence.getInstance(obj)) : null;
        }
    }
    public RecipientInfo(IssuerAndSerialNumber issuerAndserialNumber,AlgorithmIdentifier keyEncryptionAlgorithmIdentifier,ASN1SM2Cipher encryptedKey) {
        this.version = new ASN1Integer(new BigInteger("1"));
        this.issuerAndserialNumber=issuerAndserialNumber;
        this.keyEncryptionAlgorithmIdentifier=keyEncryptionAlgorithmIdentifier;
        this.encryptedKey=encryptedKey;
    }
    public RecipientInfo(ASN1Sequence sequence) {
        if (sequence.size() == 4) {
            this.version = ASN1Integer.getInstance(sequence.getObjectAt(0));
            this.issuerAndserialNumber = IssuerAndSerialNumber.getInstance(sequence.getObjectAt(1));
            this.keyEncryptionAlgorithmIdentifier = AlgorithmIdentifier.getInstance(sequence.getObjectAt(2));
            this.encryptedKey = ASN1SM2Cipher.getInstance(sequence.getObjectAt(3));
        } else {
            throw new IllegalArgumentException("Bad sequence size: " + sequence.size());
        }
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector vec = new ASN1EncodableVector(5);
        vec.add(this.version);
        vec.add(this.issuerAndserialNumber);
        vec.add(this.keyEncryptionAlgorithmIdentifier);
        vec.add(this.encryptedKey);
        return new DERSequence(vec);
    }

    @Override
    public boolean equals(Object o) {
        try {
            if (o instanceof RecipientInfo) {
                RecipientInfo oRecipientInfo = (RecipientInfo) o;
                byte[] oEncoded = oRecipientInfo.toASN1Primitive().getEncoded();
                byte[] encoded = this.toASN1Primitive().getEncoded();
                return Arrays.equals(oEncoded, encoded);
            } else {
                return false;
            }
        } catch (IOException e) {
            return false;
        }
    }
}
