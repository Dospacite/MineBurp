package io.netty.channel;

import java.net.SocketAddress;

/** Just enough of Netty's future to carry the endpoint that was connected. */
public final class ChannelFuture {
    private final SocketAddress remoteAddress;

    public ChannelFuture(SocketAddress remoteAddress) {
        this.remoteAddress = remoteAddress;
    }

    public SocketAddress remoteAddress() {
        return remoteAddress;
    }
}
