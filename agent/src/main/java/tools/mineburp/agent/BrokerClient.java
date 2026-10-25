package tools.mineburp.agent;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.lang.reflect.UndeclaredThrowableException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Loopback client for MineBurp's client-assistance broker. No access token is
 * serialized, and the capability never leaves this process: both sides prove
 * they hold it with an HMAC over fresh nonces, and the broker proves it first.
 *
 * <pre>
 * agent  → HELLO      2  &lt;agent nonce&gt;
 * broker → CHALLENGE  &lt;broker nonce&gt;  &lt;broker proof&gt;
 * agent  → AUTH       &lt;agent proof&gt;
 * broker → HELLO_OK   &lt;agent id&gt;
 * agent  → SESSION | ROUTE &lt;host&gt; &lt;port&gt;
 * </pre>
 *
 * <p>A listener that cannot produce the broker proof — a stale port taken by
 * another program after MineBurp exited, for example — learns nothing, and
 * the agent neither registers a session with it nor follows its routes.
 */
final class BrokerClient {
    static final String PROTOCOL_VERSION = "2";
    private static final long RECONNECT_DELAY_MILLIS = 1_000L;
    private static final int CONNECT_TIMEOUT_MILLIS = 1_000;
    private static final int HANDSHAKE_TIMEOUT_MILLIS = 5_000;
    private static final int ROUTE_TIMEOUT_MILLIS = 2_000;
    private static final int NONCE_LENGTH = 32;
    private static final byte[] BROKER_PROOF_LABEL =
        "mineburp-client-assistance-v2 broker".getBytes(StandardCharsets.UTF_8);
    private static final byte[] AGENT_PROOF_LABEL =
        "mineburp-client-assistance-v2 agent".getBytes(StandardCharsets.UTF_8);
    private static final SecureRandom RANDOM = new SecureRandom();
    /**
     * Minecraft's connection class under each naming scheme a client runs
     * with: Mojang names (unobfuscated releases, Forge 1.17+, NeoForge), MCP
     * names (older Forge), Fabric/Quilt intermediary, and Yarn in development.
     */
    private static final String[] CONNECTION_CLASSES = {
        "net.minecraft.network.Connection",
        "net.minecraft.network.NetworkManager",
        "net.minecraft.class_2535",
        "net.minecraft.network.ClientConnection",
    };
    private static final String NETTY_HANDLER = "io.netty.channel.SimpleChannelInboundHandler";
    private static volatile String lastReportedProblem;

    private final Path configurationPath;
    private final Map<String, PendingSession> sessions =
        new ConcurrentHashMap<String, PendingSession>();
    private final ScheduledExecutorService expiryExecutor =
        Executors.newSingleThreadScheduledExecutor(new ThreadFactory() {
            @Override
            public Thread newThread(Runnable runnable) {
                Thread thread = new Thread(runnable, "mineburp-session-expiry");
                thread.setDaemon(true);
                return thread;
            }
        });
    private final Object writeLock = new Object();
    private volatile BufferedWriter writer;
    private volatile Socket socket;

    BrokerClient(Path configurationPath) {
        this.configurationPath = configurationPath;
    }

    void start() {
        Thread connectionThread = new Thread(new Runnable() {
            @Override
            public void run() {
                connectionLoop();
            }
        }, "mineburp-client-assistance");
        connectionThread.setDaemon(true);
        connectionThread.start();
    }

    void register(String clientHash, String profileId, SessionCredential credential) {
        long now = System.currentTimeMillis();
        for (Map.Entry<String, PendingSession> entry : sessions.entrySet()) {
            if (entry.getValue().credential.expired(now)
                && sessions.remove(entry.getKey(), entry.getValue())) {
                entry.getValue().credential.clear();
            }
        }
        final PendingSession pending = new PendingSession(profileId, credential);
        PendingSession previous = sessions.put(
            clientHash,
            pending
        );
        if (previous != null) {
            previous.credential.clear();
        }
        final String expiringHash = clientHash;
        expiryExecutor.schedule(new Runnable() {
            @Override
            public void run() {
                if (sessions.remove(expiringHash, pending)) {
                    pending.credential.clear();
                }
            }
        }, 60L, TimeUnit.SECONDS);
        sendReady(clientHash, profileId);
    }

    /**
     * Opens a short-lived, authenticated route request. It intentionally does
     * not share the session-assistance connection: the broker returns after one
     * route and the long-lived connection must remain available for Authlib
     * join requests during the encryption handshake.
     */
    SocketAddress route(SocketAddress endpoint) {
        if (!(endpoint instanceof InetSocketAddress)) {
            return endpoint;
        }
        if (!isMinecraftNetworkConnect()) {
            return endpoint;
        }
        InetSocketAddress original = (InetSocketAddress) endpoint;
        if (original.getPort() <= 0 || original.getPort() > 65_535) {
            return endpoint;
        }
        InetAddress resolved = original.getAddress();
        if (resolved != null && resolved.isLoopbackAddress()) {
            return endpoint;
        }
        try {
            AgentConfiguration configuration = AgentConfiguration.load(configurationPath);
            if (!configuration.transparentIntercept) {
                return endpoint;
            }
            InetAddress brokerAddress = InetAddress.getByName(configuration.host);
            if (!brokerAddress.isLoopbackAddress()) {
                return endpoint;
            }
            return requestRoute(configuration, brokerAddress, original);
        } catch (Throwable ignored) {
            return endpoint;
        }
    }

    /**
     * Netty's Bootstrap is also used by mods and launchers. The route hook runs
     * on the thread that asked to connect, so only the frame that called
     * {@code Bootstrap#connect} is trusted, and it must be Minecraft's own
     * connection class. A mod's client started from a Minecraft tick handler
     * has Minecraft frames further down its stack, which is why "anything from
     * Minecraft on the stack" was not enough. Separate HTTPS/TLS traffic,
     * including certificate-pinned integrations, is left alone.
     *
     * <p>This only works because the seam is {@code Bootstrap#connect}. Netty
     * defers the channel's own connect to an event-loop task, where the caller
     * is no longer on the stack and nothing can be identified.
     */
    static boolean isMinecraftNetworkConnect() {
        Class<?> caller = CallerClasses.bootstrapCaller();
        return caller != null && isMinecraftConnectionClass(caller);
    }

    private static boolean isMinecraftConnectionClass(Class<?> caller) {
        Class<?> outer = caller;
        while (outer.getEnclosingClass() != null) {
            outer = outer.getEnclosingClass();
        }
        String name = outer.getName();
        for (String candidate : CONNECTION_CLASSES) {
            if (candidate.equals(name)) {
                return true;
            }
        }
        // Obfuscated releases put Minecraft in the default package under
        // names that change every version. There the connection is recognised
        // by shape: it is Netty's inbound packet handler.
        return name.indexOf('.') < 0 && extendsNettyHandler(outer);
    }

    private static boolean extendsNettyHandler(Class<?> type) {
        for (Class<?> current = type.getSuperclass(); current != null;
            current = current.getSuperclass()) {
            if (NETTY_HANDLER.equals(current.getName())) {
                return true;
            }
        }
        return false;
    }

    private SocketAddress requestRoute(
        AgentConfiguration configuration,
        InetAddress brokerAddress,
        InetSocketAddress original
    ) throws IOException {
        Socket routeSocket = new Socket();
        try {
            routeSocket.connect(
                new InetSocketAddress(brokerAddress, configuration.port),
                ROUTE_TIMEOUT_MILLIS
            );
            routeSocket.setSoTimeout(ROUTE_TIMEOUT_MILLIS);
            BufferedReader reader = new BufferedReader(new InputStreamReader(
                routeSocket.getInputStream(), StandardCharsets.UTF_8
            ));
            BufferedWriter routeWriter = new BufferedWriter(new OutputStreamWriter(
                routeSocket.getOutputStream(), StandardCharsets.UTF_8
            ));
            try {
                authenticate(reader, routeWriter, configuration);
            } catch (IOException refused) {
                report(refused);
                return original;
            }
            writeLine(
                routeWriter,
                "ROUTE\t" + encode(original.getHostString()) + "\t" + original.getPort()
            );
            String response = reader.readLine();
            String[] fields = response == null ? new String[0] : response.split("\\t", -1);
            if (fields.length != 2 || !"ROUTE_OK".equals(fields[0])) {
                return original;
            }
            int port;
            try {
                port = Integer.parseInt(fields[1]);
            } catch (NumberFormatException invalidPort) {
                return original;
            }
            if (port <= 0 || port > 65_535) {
                return original;
            }
            // Deliberately the broker's own address rather than
            // InetAddress.getLoopbackAddress(): Minecraft launches with
            // -Djava.net.preferIPv6Addresses=system, under which that returns
            // ::1, while the route listens on the IPv4 loopback the broker is
            // bound to. Connecting to the wrong loopback family is refused
            // outright, and the unused route then expires as if the client had
            // never appeared.
            return new InetSocketAddress(brokerAddress, port);
        } finally {
            try {
                routeSocket.close();
            } catch (IOException ignored) {
                // The route is already fail-open; cleanup is best effort.
            }
        }
    }

    private void connectionLoop() {
        while (!Thread.currentThread().isInterrupted()) {
            try {
                connectAndRead();
            } catch (Throwable ignored) {
                disconnect();
            }
            try {
                Thread.sleep(RECONNECT_DELAY_MILLIS);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private void connectAndRead() throws IOException {
        AgentConfiguration configuration = AgentConfiguration.load(configurationPath);
        InetAddress address = InetAddress.getByName(configuration.host);
        if (!address.isLoopbackAddress()) {
            throw new IOException("the broker address is not loopback");
        }
        Socket nextSocket = new Socket();
        nextSocket.connect(
            new InetSocketAddress(address, configuration.port),
            CONNECT_TIMEOUT_MILLIS
        );
        nextSocket.setTcpNoDelay(true);
        BufferedReader reader = new BufferedReader(new InputStreamReader(
            nextSocket.getInputStream(), StandardCharsets.UTF_8
        ));
        BufferedWriter nextWriter = new BufferedWriter(new OutputStreamWriter(
            nextSocket.getOutputStream(), StandardCharsets.UTF_8
        ));
        try {
            // Nothing is published for sendLine until the broker has proved
            // itself, so no READY can reach an unverified listener.
            nextSocket.setSoTimeout(HANDSHAKE_TIMEOUT_MILLIS);
            authenticate(reader, nextWriter, configuration);
            writeLine(nextWriter, "SESSION");
            nextSocket.setSoTimeout(0);
        } catch (IOException refused) {
            report(refused);
            try {
                nextSocket.close();
            } catch (IOException ignored) {
                // The connection is abandoned either way.
            }
            throw refused;
        }
        synchronized (writeLock) {
            socket = nextSocket;
            writer = nextWriter;
        }
        lastReportedProblem = null;
        for (Map.Entry<String, PendingSession> entry : sessions.entrySet()) {
            sendReady(entry.getKey(), entry.getValue().profileId);
        }
        String line;
        while ((line = reader.readLine()) != null) {
            handleLine(line);
        }
        throw new IOException("the broker closed the connection");
    }

    private void handleLine(String line) {
        String[] fields = line.split("\\t", -1);
        if (fields.length != 4 || !"JOIN".equals(fields[0])) {
            return;
        }
        String requestId = fields[1];
        String clientHash;
        String upstreamHash;
        try {
            UUID.fromString(requestId);
            clientHash = decode(fields[2]);
            upstreamHash = decode(fields[3]);
        } catch (IllegalArgumentException error) {
            return;
        }
        PendingSession pending = sessions.remove(clientHash);
        if (pending == null || pending.credential.expired(System.currentTimeMillis())) {
            if (pending != null) {
                pending.credential.clear();
            }
            sendResult(requestId, false, "the captured Minecraft session expired");
            return;
        }
        try {
            AgentHooks.invokeOriginal(pending.credential, upstreamHash);
            sendResult(requestId, true, "");
        } catch (Throwable error) {
            sendResult(requestId, false, safeError(error));
        }
    }

    private void sendReady(String clientHash, String profileId) {
        sendLine("READY\t" + encode(clientHash) + "\t" + encode(profileId));
    }

    private void sendResult(String requestId, boolean success, String message) {
        if (success) {
            sendLine("RESULT\t" + requestId + "\tOK");
        } else {
            sendLine("RESULT\t" + requestId + "\tERR\t" + encode(message));
        }
    }

    private void sendLine(String line) {
        synchronized (writeLock) {
            try {
                writeLineLocked(line);
            } catch (IOException error) {
                disconnectLocked();
            }
        }
    }

    private void writeLineLocked(String line) throws IOException {
        BufferedWriter current = writer;
        if (current == null) {
            return;
        }
        current.write(line);
        current.newLine();
        current.flush();
    }

    private void disconnect() {
        synchronized (writeLock) {
            disconnectLocked();
        }
    }

    private void disconnectLocked() {
        writer = null;
        Socket current = socket;
        socket = null;
        if (current != null) {
            try {
                current.close();
            } catch (IOException ignored) {
                // Nothing remains to do during reconnect cleanup.
            }
        }
    }

    /**
     * Runs the agent half of the mutual challenge. Returns once the broker has
     * accepted this agent; throws without having revealed anything if the
     * broker cannot prove it holds the capability.
     */
    static void authenticate(
        BufferedReader reader,
        BufferedWriter writer,
        AgentConfiguration configuration
    ) throws IOException {
        byte[] agentNonce = new byte[NONCE_LENGTH];
        RANDOM.nextBytes(agentNonce);
        writeLine(writer, "HELLO\t" + PROTOCOL_VERSION + "\t" + base64(agentNonce));
        String challenge = reader.readLine();
        if (challenge == null) {
            throw new IOException("the broker closed the connection during the handshake");
        }
        String[] fields = challenge.split("\\t", -1);
        if (fields.length >= 2 && "ERROR".equals(fields[0])
            && "unsupported_protocol".equals(fields[1])) {
            throw new IOException("MineBurp speaks client-assistance protocol "
                + (fields.length > 2 ? fields[2] : "?") + " but this agent speaks "
                + PROTOCOL_VERSION + "; update the agent or MineBurp so they match");
        }
        if (fields.length != 3 || !"CHALLENGE".equals(fields[0])) {
            throw new IOException("the broker sent an unexpected greeting");
        }
        byte[] brokerNonce;
        byte[] brokerProof;
        try {
            brokerNonce = unbase64(fields[1]);
            brokerProof = unbase64(fields[2]);
        } catch (IllegalArgumentException malformed) {
            throw new IOException("the broker sent a malformed challenge");
        }
        if (brokerNonce.length != NONCE_LENGTH) {
            throw new IOException("the broker sent a malformed challenge");
        }
        byte[] key = configuration.capability.getBytes(StandardCharsets.UTF_8);
        byte[] expected = proof(key, BROKER_PROOF_LABEL, agentNonce, brokerNonce);
        if (!MessageDigest.isEqual(expected, brokerProof)) {
            throw new IOException("the listener on the broker port is not this MineBurp "
                + "session; client assistance stays off");
        }
        writeLine(writer, "AUTH\t" + base64(proof(key, AGENT_PROOF_LABEL, agentNonce, brokerNonce)));
        String accepted = reader.readLine();
        if (accepted == null || !accepted.startsWith("HELLO_OK\t")) {
            throw new IOException("the broker rejected client assistance");
        }
    }

    static byte[] proof(byte[] key, byte[] label, byte[] agentNonce, byte[] brokerNonce)
        throws IOException {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            mac.update(label);
            mac.update((byte) 0);
            mac.update(agentNonce);
            mac.update(brokerNonce);
            return mac.doFinal();
        } catch (GeneralSecurityException unavailable) {
            throw new IOException("HMAC-SHA256 is unavailable", unavailable);
        }
    }

    private static void writeLine(BufferedWriter writer, String line) throws IOException {
        writer.write(line);
        writer.newLine();
        writer.flush();
    }

    /** One line per distinct problem, so a reconnect loop does not flood the log. */
    private static void report(IOException problem) {
        String message = problem.getMessage();
        if (message != null && !message.equals(lastReportedProblem)) {
            lastReportedProblem = message;
            System.err.println("[MineBurp] " + message + ".");
        }
    }

    private static String base64(byte[] value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }

    private static byte[] unbase64(String value) {
        return Base64.getUrlDecoder().decode(value);
    }

    private static String encode(String value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(
            value.getBytes(StandardCharsets.UTF_8)
        );
    }

    private static String decode(String value) {
        return new String(Base64.getUrlDecoder().decode(value), StandardCharsets.UTF_8);
    }

    private static String safeError(Throwable error) {
        Throwable current = error;
        if (current instanceof UndeclaredThrowableException
            && ((UndeclaredThrowableException) current).getUndeclaredThrowable() != null) {
            current = ((UndeclaredThrowableException) current).getUndeclaredThrowable();
        }
        return "Minecraft session join failed (" + current.getClass().getSimpleName() + ")";
    }

    private static final class PendingSession {
        final String profileId;
        final SessionCredential credential;

        PendingSession(String profileId, SessionCredential credential) {
            this.profileId = profileId;
            this.credential = credential;
        }
    }
}
