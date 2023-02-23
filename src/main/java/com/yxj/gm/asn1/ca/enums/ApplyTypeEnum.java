package com.yxj.gm.asn1.ca.enums;

public enum ApplyTypeEnum {
    APPLYKEYREQ(0),RESTOREKEYREQ(1),REVOKEKEYREQ(2);
    private int  tagNo;
    ApplyTypeEnum(int i) {
        tagNo=i;
    }
    public static ApplyTypeEnum stateOf(int index) {
        for (ApplyTypeEnum applyEnum : values()) {
            if (applyEnum.getTagNo() == index) {
                return applyEnum;
            }
        }
        return null;
    }
    public int getTagNo() {
        return tagNo;
    }

}
