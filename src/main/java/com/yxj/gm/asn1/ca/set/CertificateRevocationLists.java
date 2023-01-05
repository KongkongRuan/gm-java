package com.yxj.gm.asn1.ca.set;


import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.x509.CertificateList;

public class CertificateRevocationLists extends ASN1Object {

    private ASN1Set values;

    private CertificateRevocationLists(ASN1Set values)
    {
        this.values = values;
    }

    public static CertificateRevocationLists getInstance(Object obj)
    {
        if (obj instanceof CertificateRevocationLists)
        {
            return (CertificateRevocationLists)obj;
        }
        else if (obj != null)
        {
            return new CertificateRevocationLists(ASN1Set.getInstance(obj));
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

    public CertificateRevocationLists(CertificateList certificateList)
    {
        this.values = new DERSet(certificateList);
    }


    public CertificateRevocationLists(CertificateList[] certificateLists)
    {
        this.values = new DERSet(certificateLists);
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

    public CertificateList getFirst()
    {
        if (this.values.size() == 0)
        {
            return null;
        }

        return CertificateList.getInstance(this.values.getObjectAt(0));
    }

    public CertificateList[] getCertificateLists()
    {
        CertificateList[] tmp = new CertificateList[values.size()];

        for (int i = 0; i != tmp.length; i++)
        {
            tmp[i] = CertificateList.getInstance(values.getObjectAt(i));
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




    public ASN1Primitive toASN1Primitive()
    {
        return values;
    }

}
