package com.yxj.gm.asn1.ca.request.requestList;

import org.bouncycastle.asn1.*;

public class Request extends ASN1Object implements ASN1Choice {

    private int             tagNo;
    private ASN1Encodable    value;



    public Request(
            int tagNo,
            ASN1Encodable    value)
    {
        this.tagNo = tagNo;
        this.value = value;
    }

    private Request(
            ASN1TaggedObject    choice)
    {
        int tagNo = choice.getTagNo();

        switch (tagNo)
        {
            case 0:
                value = ApplyKeyReq.getInstance(choice, false);
                break;
            case 1:
                value = RestoreKeyReq.getInstance(choice, false);
                break;
            case 2:
                value = RevokeKeyReq.getInstance(choice, false);
                break;
            default:
                throw new IllegalArgumentException("Unknown tag encountered: " + ASN1Util.getTagText(choice));
        }

        this.tagNo = tagNo;
    }

    public static Request getInstance(
            Object  obj)
    {
        if (obj == null || obj instanceof Request)
        {
            return (Request)obj;
        }
        else if (obj instanceof ASN1TaggedObject)
        {
            return new Request((ASN1TaggedObject)obj);
        }

        throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
    }

    public static Request getInstance(
            ASN1TaggedObject obj,
            boolean          explicit)
    {
        return getInstance(obj); // must be explicitly tagged
    }

    public int getTagNo()
    {
        return tagNo;
    }

    public ASN1Encodable getStatus()
    {
        return value;
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     Request::=CHOICE{
         applykeyreq   0 IMPLICT ApplyKeyReq
         restorekeyreq 1 IMPLICT RestoreKeyReq
         revokekeyreq  2 IMPLICT RevokeKeyReq
     }
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        return new DERTaggedObject(false, tagNo, value);
    }

}
