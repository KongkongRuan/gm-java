package com.yxj.gm.asn1.ca.set;

import com.yxj.gm.asn1.ca.response.respond.envelopeddata.RecipientInfo;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERSet;

public class RecipientInfos extends ASN1Object {

    private ASN1Set values;

    private RecipientInfos(ASN1Set values)
    {
        this.values = values;
    }

    public static RecipientInfos getInstance(Object obj)
    {
        if (obj instanceof RecipientInfos)
        {
            return (RecipientInfos)obj;
        }
        else if (obj != null)
        {
            return new RecipientInfos(ASN1Set.getInstance(obj));
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

    public RecipientInfos(RecipientInfo recipientInfo)
    {
        this.values = new DERSet(recipientInfo);
    }

    /**
     * Create a multi-valued RDN.
     *
     * @param recipientInfos attribute type/value pairs making up the RDN
     */
    public RecipientInfos(RecipientInfo[] recipientInfos)
    {
        this.values = new DERSet(recipientInfos);
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

    public RecipientInfo getFirst()
    {
        if (this.values.size() == 0)
        {
            return null;
        }

        return RecipientInfo.getInstance(this.values.getObjectAt(0));
    }

    public RecipientInfo[] getRecipientInfos()
    {
        RecipientInfo[] tmp = new RecipientInfo[values.size()];

        for (int i = 0; i != tmp.length; i++)
        {
            tmp[i] = RecipientInfo.getInstance(values.getObjectAt(i));
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

    boolean containsRecipientInfo(RecipientInfo recipientInfo)
    {
        int count = values.size();
        for (int i = 0; i < count; ++i)
        {
            RecipientInfo attr = RecipientInfo.getInstance(values.getObjectAt(i));
            if (attr.equals(recipientInfo))
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
