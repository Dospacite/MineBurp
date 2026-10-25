import java.net.SocketAddress;

import io.netty.bootstrap.Bootstrap;

/** A default-package class that is not a Netty handler. Not routed. */
public final class fq {
    private fq() {
    }

    public static SocketAddress connect(SocketAddress remoteAddress) {
        return new Bootstrap().connect(remoteAddress).remoteAddress();
    }
}
