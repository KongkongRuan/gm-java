package com.yxj.gm.asn1.ca.request;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

public class AppUserInfo extends ASN1Object {
    private ASN1Integer userCertNo;
    private SubjectPublicKeyInfo userPubKey;
    private ASN1GeneralizedTime notBefore;
    private ASN1GeneralizedTime notAfter;
    private ASN1OctetString userName;
    private ASN1IA5String dsCode;
    private ASN1IA5String extendInfo;

    private static final int TAG_USER_NAME = 0;
    private static final int TAG_DS_CODE = 1;
    private static final int TAG_EXTEND_INFO = 2;

    public static AppUserInfo getInstance(ASN1TaggedObject obj, boolean explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static AppUserInfo getInstance(Object obj) {
        if (obj instanceof AppUserInfo) {
            return (AppUserInfo) obj;
        } else {
            return obj != null ? new AppUserInfo(ASN1Sequence.getInstance(obj)) : null;
        }
    }

    public AppUserInfo(ASN1Sequence sequence) {

            userCertNo = ASN1Integer.getInstance(sequence.getObjectAt(0));
            userPubKey = SubjectPublicKeyInfo.getInstance(sequence.getObjectAt(1));
            notBefore = ASN1GeneralizedTime.getInstance(sequence.getObjectAt(2));
            notAfter = ASN1GeneralizedTime.getInstance(sequence.getObjectAt(3));

            int extras = sequence.size() - 4 ;
            while (extras>0){
                ASN1TaggedObject extra=(ASN1TaggedObject)sequence.getObjectAt(4+extras-1);
                switch (extra.getTagNo()){
                    case 0:
                        userName=ASN1OctetString.getInstance(extra,true);
                        break;
                    case 1:
                        dsCode = ASN1IA5String.getInstance(extra,true);
                        break;
                    case 2:
                        extendInfo = ASN1IA5String.getInstance(extra,true);
                        break;
                    default:
                        throw new IllegalArgumentException("Unknown tag encountered in structure: " + extra.getTagNo());
                }
                extras--;
            }
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector vec = new ASN1EncodableVector();
        vec.add(userCertNo);
        vec.add(userPubKey);
        vec.add(notBefore);
        vec.add(notAfter);
        if(userName!=null){
            vec.add(new DERTaggedObject(true,0,userName));
        }
        if(dsCode!=null){
            vec.add(new DERTaggedObject(true,1,dsCode));
        }
        if(extendInfo!=null){
            vec.add(new DERTaggedObject(true,2,extendInfo));
        }
        return new DERSequence(vec);
    }

}
