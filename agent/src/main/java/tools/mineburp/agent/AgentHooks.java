package tools.mineburp.agent;

import java.net.SocketAddress;

/** Methods invoked from transformed Authlib bytecode. */
public final class AgentHooks {
    private static final ThreadLocal<Boolean> BYPASS = new ThreadLocal<Boolean>();
    private static volatile BrokerClient client;

    private AgentHooks() {
    }

    static void initialize(BrokerClient nextClient) {
        client = nextClient;
    }

    public static void beforeJoin(
        Object sessionService,
        Object identity,
        String accessToken,
        String clientServerHash
    ) {
        if (Boolean.TRUE.equals(BYPASS.get())) {
            return;
        }
        BrokerClient current = client;
        if (current == null
            || sessionService == null
            || identity == null
            || accessToken == null
            || clientServerHash == null) {
            return;
        }
        try {
            current.register(
                clientServerHash,
                profileId(identity),
                new SessionCredential(sessionService, identity, accessToken)
            );
        } catch (Throwable ignored) {
            // The original Authlib call continues even when assistance fails.
        }
    }

    static void invokeOriginal(SessionCredential credential, String upstreamHash) throws Exception {
        BYPASS.set(Boolean.TRUE);
        try {
            credential.invoke(upstreamHash);
        } finally {
            BYPASS.remove();
            credential.clear();
        }
    }

    /**
     * Called from Netty's client connect path. A route request is deliberately
     * fail-open: if MineBurp is stopped, disabled, or cannot answer quickly,
     * Minecraft connects to the original endpoint unchanged.
     */
    public static SocketAddress redirectEndpoint(SocketAddress endpoint) {
        BrokerClient current = client;
        if (current == null || endpoint == null) {
            return endpoint;
        }
        try {
            return current.route(endpoint);
        } catch (Throwable ignored) {
            return endpoint;
        }
    }

    private static String profileId(Object identity) {
        if (identity instanceof java.util.UUID) {
            return identity.toString();
        }
        try {
            Object id = identity.getClass().getMethod("getId").invoke(identity);
            return id == null ? "unknown" : id.toString();
        } catch (ReflectiveOperationException ignored) {
            return "unknown";
        }
    }
}
