package com.yxj.gm.asn1.ca.set;

import com.yxj.gm.asn1.ca.response.respond.envelopeddata.SignerInfo;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERSet;

public class SignerInfos extends ASN1Object {

    private ASN1Set values;

    private SignerInfos(ASN1Set values)
    {
        this.values = values;
    }

    public static SignerInfos getInstance(Object obj)
    {
        if (obj instanceof SignerInfos)
        {
            return (SignerInfos)obj;
        }
        else if (obj != null)
        {
            return new SignerInfos(ASN1Set.getInstance(obj));
        }

        return null;
    }

//    /**
//     * Create a single valued RecipientInfos.
//     *
//     * @param  recipientInfo
//     */
//    public RecipientInfos(RecipientInfo recipientInfo)
//    {
//        ASN1EncodableVector v = new ASN1EncodableVector(1);
//
//        v.add(recipientInfo);
//        this.values = new DERSet(new DERSequence(v));
//    }

    public SignerInfos(SignerInfo signerInfo)
    {
        this.values = new DERSet(signerInfo);
    }

    /**
     * Create a multi-valued RDN.
     *
     * @param signerInfos attribute type/value pairs making up the RDN
     */
    public SignerInfos(SignerInfo[] signerInfos)
    {
        this.values = new DERSet(signerInfos);
    }

    public boolean isMultiValued()
    {
        return this.values.size() > 1;
    }

    /**
     * Return the number of AttributeTypeAndValue objects in this RDN,
     *
     * @return size of RDN, greater than 1 if multi-valued.
     */
    public int size()
    {
        return this.values.size();
    }

    public SignerInfo getFirst()
    {
        if (this.values.size() == 0)
        {
            return null;
        }

        return SignerInfo.getInstance(this.values.getObjectAt(0));
    }

    public SignerInfo[] getRecipientInfos()
    {
        SignerInfo[] tmp = new SignerInfo[values.size()];

        for (int i = 0; i != tmp.length; i++)
        {
            tmp[i] = SignerInfo.getInstance(values.getObjectAt(i));
        }

        return tmp;
    }

//    int collectAttributeTypes(ASN1ObjectIdentifier[] oids, int oidsOff)
//    {
//        int count = values.size();
//        for (int i = 0; i < count; ++i)
//        {
//            AttributeTypeAndValue attr = AttributeTypeAndValue.getInstance(values.getObjectAt(i));
//            oids[oidsOff + i] = attr.getType();
//        }
//        return count;
//    }

    boolean containsRecipientInfo(SignerInfo signerInfo)
    {
        int count = values.size();
        for (int i = 0; i < count; ++i)
        {
            SignerInfo attr = SignerInfo.getInstance(values.getObjectAt(i));
            if (attr.equals(signerInfo))
            {
                return true;
            }
        }
        return false;
    }


    public ASN1Primitive toASN1Primitive()
    {
        return values;
    }

}
