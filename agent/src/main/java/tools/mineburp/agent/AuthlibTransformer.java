package tools.mineburp.agent;

import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.AdviceAdapter;
import org.objectweb.asm.commons.Method;

/** Instruments the one stable Authlib boundary shared by vanilla and loaders. */
final class AuthlibTransformer implements ClassFileTransformer {
    private static final String TARGET =
        "com/mojang/authlib/yggdrasil/YggdrasilMinecraftSessionService";
    private static final String LEGACY_DESCRIPTOR =
        "(Lcom/mojang/authlib/GameProfile;Ljava/lang/String;Ljava/lang/String;)V";
    private static final String MODERN_DESCRIPTOR =
        "(Ljava/util/UUID;Ljava/lang/String;Ljava/lang/String;)V";
    private static final Type HOOKS = Type.getType(AgentHooks.class);
    private static final Method BEFORE_JOIN = new Method(
        "beforeJoin",
        "(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V"
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
                    if (!"joinServer".equals(name)
                        || (!LEGACY_DESCRIPTOR.equals(descriptor)
                            && !MODERN_DESCRIPTOR.equals(descriptor))) {
                        return method;
                    }
                    return new AdviceAdapter(Opcodes.ASM9, method, access, name, descriptor) {
                        @Override
                        protected void onMethodEnter() {
                            loadThis();
                            loadArg(0);
                            loadArg(1);
                            loadArg(2);
                            invokeStatic(HOOKS, BEFORE_JOIN);
                        }
                    };
                }
            };
            // AdviceAdapter is a LocalVariablesSorter, which rejects the
            // compressed stack map frames real Authlib carries. Reading without
            // EXPAND_FRAMES threw, the catch below made it a silent skip, and
            // the session join then had no credential to work with.
            reader.accept(visitor, ClassReader.EXPAND_FRAMES);
            return writer.toByteArray();
        } catch (Throwable error) {
            System.err.println("[MineBurp] Authlib instrumentation was skipped ("
                + error + ").");
            return null;
        }
    }
}
