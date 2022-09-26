import com.yxj.gm.SM4.SM4Cipher;
import com.yxj.gm.enums.ModeEnum;
import org.bouncycastle.util.encoders.Hex;

public class TestSM4 {
    public static void main(String[] args) {
        byte[] msg = new byte[]{(byte)0x01,(byte)0x23,(byte)0x45,(byte)0x67,(byte)0x89,(byte)0xAB,(byte)0xCD,(byte)0xEF,(byte)0xFE,(byte)0xDC,(byte)0xBA,(byte)0x98,(byte)0x76,(byte)0x54,(byte)0x32,(byte)0x10,(byte)0x52,(byte)0x52};
        byte[] key = new byte[]{(byte)0x01,(byte)0x23,(byte)0x45,(byte)0x67,(byte)0x89,(byte)0xAB,(byte)0xCD,(byte)0xEF,(byte)0xFE,(byte)0xDC,(byte)0xBA,(byte)0x98,(byte)0x76,(byte)0x54,(byte)0x32,(byte)0x10};
        SM4Cipher sm4Cipher = new SM4Cipher();
        System.out.println("密钥："+Hex.toHexString(key));
        byte[] mi = sm4Cipher.cipherEncrypt(key, msg, new byte[16]);
        System.out.println("java-密文："+ Hex.toHexString(mi));
        byte[] ming = sm4Cipher.cipherDecrypt(key, mi, new byte[16]);
        System.out.println("java-明文："+Hex.toHexString(ming));
        String s1 = "hh";
        String s2 = "ss";
        String s3 = "hhss";
        String s4 = s1+s2;
        System.out.println(s3.hashCode());
        System.out.println(s4.hashCode());
        int is3 = System.identityHashCode(s3);
        System.out.println(is3);
        int is4 = System.identityHashCode(s4);
        System.out.println(is4);

        SM4Cipher sm4_ecb = new SM4Cipher(ModeEnum.ECB);
        byte[] mi_ecb = sm4_ecb.cipherEncrypt(key, msg, null);
        System.out.println("ECB密文："+Hex.toHexString(mi_ecb));
        byte[] ming_ecb = sm4_ecb.cipherDecrypt(key, mi_ecb, null);
        System.out.println("ECB明文："+Hex.toHexString(ming_ecb));

        SM4Cipher sm4_cbc = new SM4Cipher(ModeEnum.CBC);
        byte[] mi_cbc = sm4_cbc.cipherEncrypt(key, msg, new byte[16]);
        System.out.println("CBC密文："+Hex.toHexString(mi_cbc));
        byte[] ming_cbc = sm4_cbc.cipherDecrypt(key, mi_cbc, new byte[16]);
        System.out.println("CBC明文："+Hex.toHexString(ming_cbc));

    }
}
