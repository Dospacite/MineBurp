package tools.mineburp.agent.test;

import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.util.UUID;

import com.mojang.authlib.GameProfile;
import com.mojang.authlib.yggdrasil.YggdrasilMinecraftSessionService;
import net.minecraft.network.Connection;

public final class TransformerSmoke {
    /** TEST-NET-3: routable as far as the agent is concerned, never dialled. */
    private static final String TARGET_HOST = "203.0.113.5";
    private static final int TARGET_PORT = 25_565;

    private TransformerSmoke() {
    }

    public static void main(String[] arguments) throws Exception {
        int routePort = Integer.parseInt(arguments[0]);
        UUID profileId = UUID.fromString("12345678-1234-5678-90ab-1234567890ab");
        YggdrasilMinecraftSessionService service =
            new YggdrasilMinecraftSessionService();
        service.joinServer(new GameProfile(profileId), "legacy-token", "legacy-hash");
        service.joinServer(profileId, "modern-token", "modern-hash");
        Thread.sleep(1_000L);
        if (YggdrasilMinecraftSessionService.originalCalls != 2) {
            throw new AssertionError("the original Authlib methods did not both run");
        }

        InetSocketAddress endpoint = new InetSocketAddress(TARGET_HOST, TARGET_PORT);
        InetSocketAddress routed = (InetSocketAddress) Connection.connect(endpoint);
        if (!routed.getAddress().isLoopbackAddress() || routed.getPort() != routePort) {
            throw new AssertionError(
                "Minecraft's connect was not routed privately; reached " + routed);
        }
        // The route must be reachable, not merely loopback-shaped. This JVM runs
        // with Minecraft's own -Djava.net.preferIPv6Addresses=system, under which
        // the wrong loopback family is refused rather than connected.
        try (Socket probe = new Socket()) {
            probe.connect(routed, 2_000);
        } catch (Exception unreachable) {
            throw new AssertionError(
                "the private route at " + routed + " was not connectable", unreachable);
        }

        // The same seam is used by mods and launchers for their own traffic,
        // including certificate-pinned integrations. Only Minecraft's own
        // network stack may be redirected.
        SocketAddress unrelated = UnrelatedClient.connect(endpoint);
        if (!endpoint.equals(unrelated)) {
            throw new AssertionError(
                "an unrelated Netty caller was redirected to " + unrelated);
        }
    }
}
