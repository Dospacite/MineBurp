import java.net.SocketAddress;

import io.netty.bootstrap.Bootstrap;
import io.netty.channel.SimpleChannelInboundHandler;

/** An obfuscated Minecraft connection: default package, Netty handler. Routed. */
public final class ek extends SimpleChannelInboundHandler<Object> {
    private ek() {
    }

    public static SocketAddress connect(SocketAddress remoteAddress) {
        return new Bootstrap().connect(remoteAddress).remoteAddress();
    }
}
