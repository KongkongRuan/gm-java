package com.yxj.gm.asn1.ca.response.respond.envelopeddata;

import com.yxj.gm.asn1.ca.set.*;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.Certificate;

public class SignedAndEnvelopedData extends ASN1Object {
    private ASN1Integer version;
    private RecipientInfos recipientInfos;
    private DigestAlgorithmIdentifiers digestAlgorithms;
    private EncryptedContentInfo encryptedContentInfo;
    private ExtendedCertificatesAndCertificates certificates; //OPTIONAL
    private CertificateRevocationLists crls; //OPTIONAL
    private SignerInfos signerInfos;


    public static SignedAndEnvelopedData getInstance(ASN1TaggedObject obj, boolean explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static SignedAndEnvelopedData getInstance(Object obj) {
        if (obj instanceof SignedAndEnvelopedData) {
            return (SignedAndEnvelopedData) obj;
        } else {
            return obj != null ? new SignedAndEnvelopedData(ASN1Sequence.getInstance(obj)) : null;
        }
    }

    public SignedAndEnvelopedData(ASN1Sequence sequence) {
        version = ASN1Integer.getInstance(sequence.getObjectAt(0));
        recipientInfos = RecipientInfos.getInstance(sequence.getObjectAt(1));
        digestAlgorithms = DigestAlgorithmIdentifiers.getInstance(sequence.getObjectAt(2));
        encryptedContentInfo = EncryptedContentInfo.getInstance(sequence.getObjectAt(3));
        int extras = sequence.size() - 5 ;
        while (extras>0){
            ASN1TaggedObject extra=(ASN1TaggedObject)sequence.getObjectAt(4+extras-1);
            switch (extra.getTagNo()){
                case 0:
                    certificates=ExtendedCertificatesAndCertificates.getInstance(extra);
                    break;
                case 1:
                    crls = CertificateRevocationLists.getInstance(extra);
                    break;
                default:
                    throw new IllegalArgumentException("Unknown tag encountered in structure: " + extra.getTagNo());
            }
            extras--;
        }
        signerInfos = SignerInfos.getInstance(sequence.getObjectAt(extras+4));
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector vec = new ASN1EncodableVector();
        vec.add(version);
        vec.add(recipientInfos);
        vec.add(digestAlgorithms);
        vec.add(encryptedContentInfo);
        if(certificates!=null){
            vec.add(new DERTaggedObject(false,0,certificates));
        }
        if(crls!=null){
            vec.add(new DERTaggedObject(false,1,crls));
        }
        vec.add(signerInfos);

        return new DERSequence(vec);
    }
}
