package tools.mineburp.agent;

import java.lang.instrument.Instrumentation;
import java.nio.file.Path;
import java.nio.file.Paths;

/** Startup entry point for loader-independent Minecraft client assistance. */
public final class MineBurpAgent {
    private MineBurpAgent() {
    }

    public static void premain(String agentArguments, Instrumentation instrumentation) {
        try {
            Path configurationPath = parseConfigurationPath(agentArguments);
            BrokerClient client = new BrokerClient(configurationPath);
            AgentHooks.initialize(client);
            instrumentation.addTransformer(new AuthlibTransformer(), false);
            instrumentation.addTransformer(new NettyTransformer(), false);
            client.start();
        } catch (Throwable error) {
            // Client assistance must never prevent Minecraft from starting.
            System.err.println("[MineBurp] Client assistance is unavailable ("
                + error.getClass().getSimpleName() + ").");
        }
    }

    private static Path parseConfigurationPath(String arguments) {
        if (arguments == null || !arguments.startsWith("config=")) {
            throw new IllegalArgumentException("expected -javaagent options to contain config=<path>");
        }
        String value = arguments.substring("config=".length()).trim();
        if (value.length() >= 2 && value.startsWith("\"") && value.endsWith("\"")) {
            value = value.substring(1, value.length() - 1);
        }
        if (value.isEmpty()) {
            throw new IllegalArgumentException("the client-assistance configuration path is empty");
        }
        return Paths.get(value).toAbsolutePath().normalize();
    }
}
