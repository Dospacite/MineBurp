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
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;

/** Capability-authenticated loopback client. No access token is serialized. */
final class BrokerClient {
    private static final long RECONNECT_DELAY_MILLIS = 1_000L;
    private static final int CONNECT_TIMEOUT_MILLIS = 1_000;
    private static final int ROUTE_TIMEOUT_MILLIS = 2_000;

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
     * on the thread that asked to connect, so require Minecraft's own network
     * package on that stack before touching a destination. This leaves separate
     * HTTPS/TLS traffic alone, including certificate-pinned integrations.
     *
     * <p>This only works because the seam is {@code Bootstrap#connect}. Netty
     * defers the channel's own connect to an event-loop task, where the caller
     * is no longer on the stack and nothing can be identified.
     */
    private static boolean isMinecraftNetworkConnect() {
        for (StackTraceElement frame : Thread.currentThread().getStackTrace()) {
            if (frame.getClassName().startsWith("net.minecraft.")) {
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
            routeWriter.write("HELLO\t1\t" + configuration.capability);
            routeWriter.newLine();
            routeWriter.flush();
            String hello = reader.readLine();
            if (hello == null || !hello.startsWith("HELLO_OK\t")) {
                return original;
            }
            routeWriter.write(
                "ROUTE\t" + encode(original.getHostString()) + "\t" + original.getPort()
            );
            routeWriter.newLine();
            routeWriter.flush();
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
        synchronized (writeLock) {
            socket = nextSocket;
            writer = nextWriter;
            writeLineLocked("HELLO\t1\t" + configuration.capability);
        }
        String response = reader.readLine();
        if (response == null || !response.startsWith("HELLO_OK\t")) {
            throw new IOException("the broker rejected client assistance");
        }
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
