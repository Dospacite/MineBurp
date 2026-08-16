package tools.mineburp.agent;

import java.lang.instrument.ClassFileTransformer;
import java.net.SocketAddress;
import java.security.ProtectionDomain;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.AdviceAdapter;
import org.objectweb.asm.commons.Method;

/**
 * Rewrites the destination Netty is asked to connect to. Minecraft continues to
 * own its socket and sees a normal loopback connection; MineBurp obtains the
 * original host and port through the capability-protected route request.
 *
 * <p>The seam is {@code Bootstrap#connect}, not the channel's {@code doConnect}.
 * Netty hands the actual connect to the event loop as a task, so by the time a
 * channel connects there is no caller left on the stack — the route hook's
 * "is this Minecraft?" check could never pass there, and which channel class
 * even runs depends on whether a native transport is available. {@code connect}
 * runs on the thread that asked for the connection, which is both the only
 * place the caller can be identified and the same for every transport.
 */
final class NettyTransformer implements ClassFileTransformer {
    private static final String TARGET = "io/netty/bootstrap/Bootstrap";
    private static final String CONNECT = "connect";
    /** Every public overload funnels into one of these two. */
    private static final String[] CONNECT_DESCRIPTORS = {
        "(Ljava/net/SocketAddress;)Lio/netty/channel/ChannelFuture;",
        "(Ljava/net/SocketAddress;Ljava/net/SocketAddress;)Lio/netty/channel/ChannelFuture;",
    };
    private static final Type HOOKS = Type.getType(AgentHooks.class);
    private static final Type SOCKET_ADDRESS = Type.getType(SocketAddress.class);
    private static final Method REDIRECT_ENDPOINT = new Method(
        "redirectEndpoint", "(Ljava/net/SocketAddress;)Ljava/net/SocketAddress;"
    );

    @Override
    public byte[] transform(
        ClassLoader loader,
        String className,
        Class<?> classBeingRedefined,
        ProtectionDomain protectionDomain,
        byte[] classfileBuffer
    ) {
        if (!TARGET.equals(className)) {
            return null;
        }
        try {
            ClassReader reader = new ClassReader(classfileBuffer);
            ClassWriter writer = new ClassWriter(reader, ClassWriter.COMPUTE_MAXS);
            ClassVisitor visitor = new ClassVisitor(Opcodes.ASM9, writer) {
                @Override
                public MethodVisitor visitMethod(
                    int access,
                    String name,
                    String descriptor,
                    String signature,
                    String[] exceptions
                ) {
                    MethodVisitor method = super.visitMethod(
                        access, name, descriptor, signature, exceptions
                    );
                    if (!CONNECT.equals(name) || !isConnectDescriptor(descriptor)) {
                        return method;
                    }
                    return new AdviceAdapter(Opcodes.ASM9, method, access, name, descriptor) {
                        @Override
                        protected void onMethodEnter() {
                            loadArg(0);
                            invokeStatic(HOOKS, REDIRECT_ENDPOINT);
                            checkCast(SOCKET_ADDRESS);
                            storeArg(0);
                        }
                    };
                }
            };
            // AdviceAdapter is a LocalVariablesSorter, which rejects the
            // compressed stack map frames every real Netty class carries.
            // Reading without EXPAND_FRAMES threw on the first branch in the
            // method, and the catch below turned that into a silent skip: the
            // hook was never installed on any production client.
            reader.accept(visitor, ClassReader.EXPAND_FRAMES);
            return writer.toByteArray();
        } catch (Throwable error) {
            System.err.println("[MineBurp] Netty route instrumentation was skipped for "
                + className + " (" + error + ").");
            return null;
        }
    }

    private static boolean isConnectDescriptor(String descriptor) {
        for (String candidate : CONNECT_DESCRIPTORS) {
            if (candidate.equals(descriptor)) {
                return true;
            }
        }
        return false;
    }
}
