package com.yxj.gm.tls.netty;

import com.yxj.gm.tls.netty.handler.server.NettyTlsServerHandler;
import com.yxj.gm.util.FileUtils;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.DelimiterBasedFrameDecoder;
import io.netty.handler.codec.LengthFieldBasedFrameDecoder;
import org.bouncycastle.util.encoders.Hex;

import javax.lang.model.element.VariableElement;
import java.io.File;
import java.sql.SQLOutput;

public class NettyTlsServer {
    private int tlsPort = 4433;

    private NettyTlsServerHandler nettyTlsServerHandler=new NettyTlsServerHandler();

    public NettyTlsServer() {
    }
    public NettyTlsServer(int tlsPort) {
        this.tlsPort = tlsPort;
    }
    public NettyTlsServer(int tlsPort,byte[] serverCert,byte[] serverPriKey) {
        this.tlsPort = tlsPort;
        nettyTlsServerHandler=new NettyTlsServerHandler(serverCert,serverPriKey);
    }
    EventLoopGroup bossGroup = new NioEventLoopGroup();
    EventLoopGroup workerGroup = new NioEventLoopGroup();
    public void shutdown(){
        bossGroup.shutdownGracefully();
        workerGroup.shutdownGracefully();
    }
    public void start() throws Exception {
        try {
            ServerBootstrap serverBootstrap = new ServerBootstrap();
            serverBootstrap.group(bossGroup, workerGroup)
                    .channel(NioServerSocketChannel.class)
                    .childHandler(new ChannelInitializer<SocketChannel>() {
                        @Override
                        protected void initChannel(SocketChannel ch) throws Exception {

                            ch.pipeline().addLast(new DelimiterBasedFrameDecoder(10240,NettyConstant.Delimiter));
                            ch.pipeline().addLast(nettyTlsServerHandler); // 自定义处理器
                        }
                    })
                    .option(ChannelOption.SO_BACKLOG, 128)
                    .childOption(ChannelOption.SO_KEEPALIVE, true);
            if (NettyConstant.FIRSTPRINT)System.out.println("netty-tls-server:serverStart");
            ChannelFuture future = serverBootstrap.bind(tlsPort).sync();
            future.channel().closeFuture().sync();
        } finally {
            workerGroup.shutdownGracefully();
            bossGroup.shutdownGracefully();
        }
    }
    public byte[] getRandom(){
        return nettyTlsServerHandler.getRandom();
    }

    public static void main(String[] args) throws Exception {
        byte[] cert = FileUtils.readFileToByteArray(new File("D:\\certtest\\java-ca.cer"));
        byte[] pri = FileUtils.readFileToByteArray(new File("D:\\certtest\\java-ca.pri"));
        NettyTlsServer nettyTlsServer = new NettyTlsServer(4432,cert,pri);

        new Thread(()->{
            try {
                nettyTlsServer.start();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }).start();
//        NettyTlsServer nettyTlsServer = new NettyTlsServer(4432);
//        nettyTlsServer.start();

        while (true){
            System.out.println("server sleep");
            Thread.sleep(1000);
            if(nettyTlsServer.getRandom()!=null){
                System.out.println(Hex.toHexString(nettyTlsServer.getRandom()));
                break;
            }
        }
        nettyTlsServer.shutdown();

    }
}

