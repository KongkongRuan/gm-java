package com.yxj.gm.enums;

public enum ModeEnum {
    ECB(1),CBC(2),CFB(3),OFB(4),CTR(5);
    private int code;
    private ModeEnum(int code){
        this.code=code;
    }
    public int getCode() {
        return code;
    }
}
