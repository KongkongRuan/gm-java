package com.yxj.gm.asn1.ca.response.respond;

import org.bouncycastle.asn1.*;

public class ErrorPkgRespond extends ASN1Object {

    private ASN1Integer errNo;
    private ErrDesc errDesc;





    public static ErrorPkgRespond getInstance(ASN1TaggedObject obj, boolean explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static ErrorPkgRespond getInstance(Object obj) {
        if (obj instanceof ErrorPkgRespond) {
            return (ErrorPkgRespond) obj;
        } else {
            return obj != null ? new ErrorPkgRespond(ASN1Sequence.getInstance(obj)) : null;
        }
    }

    public ErrorPkgRespond(ASN1Sequence sequence) {

            errNo = ASN1Integer.getInstance(sequence.getObjectAt(0));
        if(sequence.size()==2) {
            errDesc=ErrDesc.getInstance(sequence.getObjectAt(1));
        }else {
            throw new IllegalArgumentException("Bad sequence size: " + sequence.size());
        }
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector vec = new ASN1EncodableVector();
        vec.add(errNo);
        if(errDesc!=null){
            vec.add(new DERTaggedObject(true,0,errDesc));
        }
        return new DERSequence(vec);
    }
}
