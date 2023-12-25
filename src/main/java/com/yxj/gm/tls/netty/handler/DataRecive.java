package com.yxj.gm.tls.netty.handler;

public class DataRecive {
    private int totalLength = 0;
    private byte[] currentContent = null;

    private boolean isComplete = true;

    public int getTotalLength() {
        return totalLength;
    }

    public void setTotalLength(int totalLength) {
        this.totalLength = totalLength;
    }

    public void reset() {
        this.totalLength = 0;
        this.currentContent = null;
        this.isComplete = true;
    }

    public byte[] getCurrentContent() {
        return currentContent;
    }

    public void setCurrentContent(byte[] currentContent) {
        this.currentContent = currentContent;
    }

    public boolean isComplete() {
        return isComplete;
    }

    public void setComplete(boolean complete) {
        isComplete = complete;
    }
}
