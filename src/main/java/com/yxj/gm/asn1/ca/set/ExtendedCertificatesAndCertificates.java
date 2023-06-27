package com.yxj.gm.asn1.ca.set;

import com.yxj.gm.asn1.ca.response.respond.envelopeddata.ExtendedCertificateOrCertificate;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERSet;

public class ExtendedCertificatesAndCertificates extends ASN1Object {
    private ASN1Set values;

    private ExtendedCertificatesAndCertificates(ASN1Set values)
    {
        this.values = values;
    }

    public static ExtendedCertificatesAndCertificates getInstance(Object obj)
    {
        if (obj instanceof ExtendedCertificatesAndCertificates)
        {
            return (ExtendedCertificatesAndCertificates)obj;
        }
        else if (obj != null)
        {
            return new ExtendedCertificatesAndCertificates(ASN1Set.getInstance(obj));
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

    public ExtendedCertificatesAndCertificates(ExtendedCertificateOrCertificate extendedCertificateOrCertificate)
    {
        this.values = new DERSet(extendedCertificateOrCertificate);
    }

    /**
     * Create a multi-valued RDN.
     *
     * @param extendedCertificateOrCertificates attribute type/value pairs making up the RDN
     */
    public ExtendedCertificatesAndCertificates(ExtendedCertificateOrCertificate[] extendedCertificateOrCertificates)
    {
        this.values = new DERSet(extendedCertificateOrCertificates);
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

    public ExtendedCertificateOrCertificate getFirst()
    {
        if (this.values.size() == 0)
        {
            return null;
        }

        return ExtendedCertificateOrCertificate.getInstance(this.values.getObjectAt(0));
    }

    public ExtendedCertificateOrCertificate[] extendedCertificateOrCertificates()
    {
        ExtendedCertificateOrCertificate[] tmp = new ExtendedCertificateOrCertificate[values.size()];

        for (int i = 0; i != tmp.length; i++)
        {
            tmp[i] = ExtendedCertificateOrCertificate.getInstance(values.getObjectAt(i));
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

//    boolean containsRecipientInfo(AlgorithmIdentifier algorithmIdentifier)
//    {
//        int count = values.size();
//        for (int i = 0; i < count; ++i)
//        {
//            AlgorithmIdentifier attr = AlgorithmIdentifier.getInstance(values.getObjectAt(i));
//            if (attr.equals(algorithmIdentifier))
//            {
//                return true;
//            }
//        }
//        return false;
//    }


    public ASN1Primitive toASN1Primitive()
    {
        return values;
    }
}
