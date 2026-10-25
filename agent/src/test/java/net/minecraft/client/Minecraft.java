package net.minecraft.client;

import java.net.SocketAddress;

import tools.mineburp.agent.test.UnrelatedClient;

/**
 * A Minecraft frame further down the stack than the connect call: a mod's own
 * Netty client started from a tick handler. Must not be routed.
 */
public final class Minecraft {
    private Minecraft() {
    }

    public static SocketAddress tickModClient(SocketAddress remoteAddress) {
        return UnrelatedClient.connect(remoteAddress);
    }
}
