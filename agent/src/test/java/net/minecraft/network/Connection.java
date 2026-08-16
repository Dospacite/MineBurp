package net.minecraft.network;

import java.net.SocketAddress;

import io.netty.bootstrap.Bootstrap;

/** Supplies the Minecraft stack frame the route safety gate requires. */
public final class Connection {
    private Connection() {
    }

    public static SocketAddress connect(SocketAddress remoteAddress) {
        return new Bootstrap().connect(remoteAddress).remoteAddress();
    }
}
