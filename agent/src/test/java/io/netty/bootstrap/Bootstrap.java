package io.netty.bootstrap;

import java.net.InetSocketAddress;
import java.net.SocketAddress;

import io.netty.channel.ChannelFuture;

/**
 * A binary-compatible stand-in for Netty's connect seam.
 *
 * <p>The branches and the loop are deliberate: javac emits a StackMapTable for
 * them, which is what every real Netty class carries. A straight-line stub let a
 * transformer that could not handle compressed frames pass this test while
 * failing on every production client.
 */
public final class Bootstrap {
    public ChannelFuture connect(SocketAddress remoteAddress) {
        if (remoteAddress == null) {
            throw new IllegalArgumentException("remoteAddress");
        }
        SocketAddress connected = null;
        for (int attempt = 0; attempt < 2; attempt++) {
            if (attempt > 0) {
                connected = remoteAddress;
            }
        }
        return new ChannelFuture(connected);
    }

    public ChannelFuture connect(String host, int port) {
        return connect(InetSocketAddress.createUnresolved(host, port));
    }
}
