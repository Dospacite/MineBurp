package tools.mineburp.agent.test;

import java.net.SocketAddress;

import io.netty.bootstrap.Bootstrap;

/** A mod or launcher using Netty for its own traffic. Must not be routed. */
public final class UnrelatedClient {
    private UnrelatedClient() {
    }

    public static SocketAddress connect(SocketAddress remoteAddress) {
        return new Bootstrap().connect(remoteAddress).remoteAddress();
    }
}
