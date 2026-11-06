package tools.mineburp.agent.test;

import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.util.UUID;

import com.mojang.authlib.GameProfile;
import com.mojang.authlib.yggdrasil.YggdrasilMinecraftSessionService;
import net.minecraft.client.Minecraft;
import net.minecraft.network.Connection;

/**
 * Runs inside a JVM with the agent attached.
 *
 * <p>{@code trusted}: the broker proves the capability, so Authlib joins are
 * registered and Minecraft's connects are routed. {@code refused}: the broker
 * cannot prove it, so nothing is routed and Minecraft behaves as if MineBurp
 * were absent.
 */
public final class TransformerSmoke {
    /** TEST-NET-3: routable as far as the agent is concerned, never dialled. */
    private static final String TARGET_HOST = "203.0.113.5";
    private static final int TARGET_PORT = 25_565;

    private TransformerSmoke() {
    }

    public static void main(String[] arguments) throws Exception {
        int routePort = Integer.parseInt(arguments[0]);
        boolean trusted = "trusted".equals(arguments[1]);
        UUID profileId = UUID.fromString("12345678-1234-5678-90ab-1234567890ab");
        YggdrasilMinecraftSessionService service =
            new YggdrasilMinecraftSessionService();
        service.joinServer(new GameProfile(profileId), "legacy-token", "legacy-hash");
        service.joinServer(profileId, "modern-token", "modern-hash");
        Thread.sleep(1_000L);
        if (YggdrasilMinecraftSessionService.originalCalls != (trusted ? 4 : 2)) {
            throw new AssertionError("the original Authlib methods did not both run");
        }

        InetSocketAddress endpoint = new InetSocketAddress(TARGET_HOST, TARGET_PORT);
        SocketAddress minecraft = Connection.connect(endpoint);
        SocketAddress obfuscated = invoke("ek", endpoint);
        if (!trusted) {
            // An unverified listener must not be able to redirect the game.
            expectUnchanged("Minecraft's connect under an unverified broker", endpoint, minecraft);
            expectUnchanged("an obfuscated connect under an unverified broker", endpoint, obfuscated);
            return;
        }
        // Exercise the same invocation seam and inspect the credential after
        // return, so removing it from the broker map alone cannot pass.
        Class<?> credentialType = Class.forName("tools.mineburp.agent.SessionCredential");
        java.lang.reflect.Constructor<?> constructor = credentialType.getDeclaredConstructor(
            Object.class, Object.class, String.class);
        constructor.setAccessible(true);
        Object credential = constructor.newInstance(service, profileId, "test-token");
        Method invokeOriginal = Class.forName("tools.mineburp.agent.AgentHooks")
            .getDeclaredMethod("invokeOriginal", credentialType, String.class);
        invokeOriginal.setAccessible(true);
        invokeOriginal.invoke(null, credential, "internal-join-hash");
        for (String fieldName : new String[] { "sessionService", "identity", "accessToken" }) {
            java.lang.reflect.Field field = credentialType.getDeclaredField(fieldName);
            field.setAccessible(true);
            if (field.get(credential) != null) {
                throw new AssertionError("JOIN retained " + fieldName);
            }
        }
        expectRouted("Minecraft's connect", minecraft, routePort);
        expectRouted("an obfuscated Minecraft connect", obfuscated, routePort);

        // The same seam is used by mods and launchers for their own traffic,
        // including certificate-pinned integrations. Only Minecraft's own
        // connection class may be redirected, even when Minecraft frames sit
        // further down the stack.
        expectUnchanged("an unrelated Netty caller", endpoint, UnrelatedClient.connect(endpoint));
        expectUnchanged("a mod client started from Minecraft", endpoint,
            Minecraft.tickModClient(endpoint));
        expectUnchanged("a default-package class that is not a connection", endpoint,
            invoke("fq", endpoint));
    }

    private static SocketAddress invoke(String className, SocketAddress endpoint)
        throws Exception {
        // Default-package classes cannot be imported from a named package.
        Method connect = Class.forName(className).getMethod("connect", SocketAddress.class);
        return (SocketAddress) connect.invoke(null, endpoint);
    }

    private static void expectRouted(String what, SocketAddress result, int routePort) {
        InetSocketAddress routed = (InetSocketAddress) result;
        if (!routed.getAddress().isLoopbackAddress() || routed.getPort() != routePort) {
            throw new AssertionError(what + " was not routed privately; reached " + routed);
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
    }

    private static void expectUnchanged(
        String what,
        SocketAddress endpoint,
        SocketAddress result
    ) {
        if (!endpoint.equals(result)) {
            throw new AssertionError(what + " was redirected to " + result);
        }
    }
}
