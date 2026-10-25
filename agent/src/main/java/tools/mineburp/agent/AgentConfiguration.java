package tools.mineburp.agent;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;

final class AgentConfiguration {
    final String host;
    final int port;
    final String capability;
    final boolean transparentIntercept;

    private AgentConfiguration(
        String host,
        int port,
        String capability,
        boolean transparentIntercept
    ) {
        this.host = host;
        this.port = port;
        this.capability = capability;
        this.transparentIntercept = transparentIntercept;
    }

    static AgentConfiguration load(Path path) throws IOException {
        Properties properties = new Properties();
        try (InputStream input = Files.newInputStream(path)) {
            properties.load(input);
        }
        String protocol = properties.getProperty("protocol");
        if (!BrokerClient.PROTOCOL_VERSION.equals(protocol)) {
            throw new IOException("MineBurp wrote client-assistance protocol " + protocol
                + " but this agent speaks " + BrokerClient.PROTOCOL_VERSION
                + "; update the agent or MineBurp so they match");
        }
        String host = required(properties, "host");
        int port;
        try {
            port = Integer.parseInt(required(properties, "port"));
        } catch (NumberFormatException error) {
            throw new IOException("invalid broker port", error);
        }
        if (port <= 0 || port > 65535) {
            throw new IOException("invalid broker port");
        }
        return new AgentConfiguration(
            host,
            port,
            required(properties, "capability"),
            Boolean.parseBoolean(properties.getProperty("transparent_intercept", "false"))
        );
    }

    private static String required(Properties properties, String key) throws IOException {
        String value = properties.getProperty(key);
        if (value == null || value.trim().isEmpty()) {
            throw new IOException("missing " + key);
        }
        return value.trim();
    }
}
