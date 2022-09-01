import com.yxj.gm.SM2.Cipher.SM2Cipher;
import com.yxj.gm.SM2.Key.SM2;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.security.*;
import java.util.concurrent.CountDownLatch;

public class TestMultithreading {

    String msg ="xdyg123.";

    public static void main(String[] args) {
        CountDownLatch c = new CountDownLatch(3);
        Thread timeThread = new Thread(new TimeThread(c));
        Thread workerThread1 = new Thread(new WorkerThread(c));
        Thread workerThread2 = new Thread(new WorkerThread(c));
        Thread workerThread3 = new Thread(new WorkerThread(c));
        Thread workerThread4 = new Thread(new WorkerThread(c));
        Thread workerThread5 = new Thread(new WorkerThread(c));
        Thread workerThread6 = new Thread(new WorkerThread(c));
        Thread workerThread7 = new Thread(new WorkerThread(c));
        Thread workerThread8 = new Thread(new WorkerThread(c));

        timeThread.start();
        workerThread1.start();
        workerThread2.start();
        workerThread3.start();
        workerThread4.start();
        workerThread5.start();
        workerThread6.start();
        workerThread7.start();
        workerThread8.start();
    }
    static class TimeThread implements Runnable{
        CountDownLatch c ;
        TimeThread(){
        }
        TimeThread(CountDownLatch c){
            this.c=c;
        }
        public void run() {
            long start = System.currentTimeMillis();
            try {
                c.await();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            System.out.println("执行结束："+(System.currentTimeMillis()-start));
            System.out.println("执行结束："+(System.currentTimeMillis()-start)/200.0);
        }
    }
    static class WorkerThread implements Runnable{
        CountDownLatch c;
        WorkerThread(){};
        WorkerThread(CountDownLatch c){
            this.c=c;
        }
        public void run(){
            SM2Cipher cipher = new SM2Cipher();
            for (int i = 0; i < 250000000; i++) {
                KeyPair keyPair = SM2.generateSM2KeyPair();
//                KeyPair keyPair = useKey.keyPairGenerator("SM2");
//                System.out.println(Hex.toHexString(keyPair.getPublic().getEncoded()));
//                System.out.println(Hex.toHexString(keyPair.getPrivate().getEncoded()));
//                byte[] bytes = cipher.SM2CipherEncrypt("xdyg123.".getBytes(), keyPair.getPublic().getEncoded());
//                byte[] ming = cipher.SM2CipherDecrypt(bytes, keyPair.getPrivate().getEncoded());
//                if(new String(ming).equals("xdyg123.")){
//                    System.out.println(Thread.currentThread().getName()+"-"+i);
//                }else {
//                    System.err.println(Thread.currentThread().getName()+"-"+i);
//                }
                                    System.out.println(Thread.currentThread().getName()+"-"+i);

            }
            c.countDown();
        }
    }
}
