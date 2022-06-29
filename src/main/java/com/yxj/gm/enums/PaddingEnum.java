package com.yxj.gm.enums;

public enum PaddingEnum {
    Pkcs7(1),Pkcs5(2);
    private int code;
    private PaddingEnum(int code){
        this.code=code;
    }
    public int getCode() {
        return code;
    }
}
