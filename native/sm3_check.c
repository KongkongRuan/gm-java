#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

static const uint32_t IV[8] = {
    0x7380166fU, 0x4914b2b9U, 0x172442d7U, 0xda8a0600U,
    0xa96f30bcU, 0x163138aaU, 0xe38dee4dU, 0xb0fb0e4eU
};
static uint32_t rol(uint32_t x, int n){ return (x<<n)|(x>>(32-n)); }
static uint32_t p0(uint32_t x){ return x^rol(x,9)^rol(x,17); }
static uint32_t p1(uint32_t x){ return x^rol(x,15)^rol(x,23); }
static void be32_to_bytes(const uint32_t *in, uint8_t *out, int n){
    for(int i=0;i<n;i++){ out[i*4]=in[i]>>24; out[i*4+1]=in[i]>>16; out[i*4+2]=in[i]>>8; out[i*4+3]=in[i]; }
}
static void sm3_cf(uint32_t s[8], const uint8_t blk[64]){
    uint32_t W[68],W1[64];
    for(int i=0;i<16;i++) W[i]=((uint32_t)blk[i*4]<<24)|((uint32_t)blk[i*4+1]<<16)|((uint32_t)blk[i*4+2]<<8)|blk[i*4+3];
    for(int j=16;j<68;j++) W[j]=p1(W[j-16]^W[j-9]^rol(W[j-3],15))^rol(W[j-13],7)^W[j-6];
    for(int j=0;j<64;j++) W1[j]=W[j]^W[j+4];
    uint32_t A=s[0],B=s[1],C=s[2],D=s[3],E=s[4],F=s[5],G=s[6],H=s[7];
    for(int j=0;j<16;j++){
        uint32_t T=rol(0x79cc4519,j);
        uint32_t SS1=rol(rol(A,12)+E+T,7);
        uint32_t SS2=SS1^rol(A,12);
        uint32_t TT1=(A^B^C)+D+SS2+W1[j];
        uint32_t TT2=(E^F^G)+H+SS1+W[j];
        D=C; C=rol(B,9); B=A; A=TT1; H=G; G=rol(F,19); F=E; E=p0(TT2);
    }
    for(int j=16;j<64;j++){
        uint32_t T=rol(0x7a879d8a,j);
        uint32_t SS1=rol(rol(A,12)+E+T,7);
        uint32_t SS2=SS1^rol(A,12);
        uint32_t TT1=((A&B)|(A&C)|(B&C))+D+SS2+W1[j];
        uint32_t TT2=((E&F)|(~E&G))+H+SS1+W[j];
        D=C; C=rol(B,9); B=A; A=TT1; H=G; G=rol(F,19); F=E; E=p0(TT2);
    }
    s[0]^=A; s[1]^=B; s[2]^=C; s[3]^=D; s[4]^=E; s[5]^=F; s[6]^=G; s[7]^=H;
}
static void sm3(const uint8_t *msg, size_t len, uint8_t d[32]){
    uint32_t s[8]; memcpy(s,IV,sizeof(s));
    size_t blocks=len/64;
    for(size_t i=0;i<blocks;i++) sm3_cf(s,msg+i*64);
    uint8_t fb[128];
    size_t rem=len%64;
    memcpy(fb,msg+blocks*64,rem);
    fb[rem]=0x80;
    size_t fl=rem<=55?64:128;
    if(rem+1<fl) memset(fb+rem+1,0,fl-rem-9);
    uint64_t bl=(uint64_t)len*8;
    for(int i=0;i<8;i++) fb[fl-1-i]=(uint8_t)(bl>>(i*8));
    sm3_cf(s,fb);
    if(fl==128) sm3_cf(s,fb+64);
    be32_to_bytes(s,d,8);
}
int main(int argc,char**argv){
    for(int len=0;len<=10;len++){
        uint8_t *data=malloc(len);
        for(int i=0;i<len;i++) data[i]=(uint8_t)i;
        uint8_t d[32];
        sm3(data,len,d);
        printf("len=%2d: ",len);
        for(int i=0;i<32;i++) printf("%02x",d[i]);
        printf("\n");
        free(data);
    }
    return 0;
}
