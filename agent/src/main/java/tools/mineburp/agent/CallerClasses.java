package tools.mineburp.agent;

import java.lang.reflect.Method;
import java.util.function.Function;
import java.util.stream.Stream;

/**
 * Finds the class that called Netty's {@code Bootstrap#connect}.
 *
 * <p>Class references rather than names, because a name alone cannot tell an
 * obfuscated Minecraft class from any other default-package class. Java 9+
 * uses {@code StackWalker} through reflection so the agent still compiles for
 * Java 8, where {@code SecurityManager#getClassContext} does the same job.
 */
final class CallerClasses {
    private static final String BOOTSTRAP = "io.netty.bootstrap.Bootstrap";
    private static final String ABSTRACT_BOOTSTRAP = "io.netty.bootstrap.AbstractBootstrap";
    private static final Walker WALKER = createWalker();

    private CallerClasses() {
    }

    /** The first frame below Netty's bootstrap, or null if there is none. */
    static Class<?> bootstrapCaller() {
        Class<?>[] stack;
        try {
            stack = WALKER.classes();
        } catch (Throwable unavailable) {
            return null;
        }
        boolean insideBootstrap = false;
        for (Class<?> type : stack) {
            if (type == null) {
                continue;
            }
            boolean bootstrap = isBootstrap(type);
            if (bootstrap) {
                insideBootstrap = true;
            } else if (insideBootstrap) {
                return type;
            }
        }
        return null;
    }

    private static boolean isBootstrap(Class<?> type) {
        String name = type.getName();
        return BOOTSTRAP.equals(name) || ABSTRACT_BOOTSTRAP.equals(name);
    }

    private interface Walker {
        Class<?>[] classes() throws Exception;
    }

    private static Walker createWalker() {
        try {
            return new StackWalkerWalker();
        } catch (Throwable java8) {
            return new ClassContextWalker();
        }
    }

    /** Java 9+: {@code StackWalker} with retained class references. */
    private static final class StackWalkerWalker implements Walker {
        private final Object walker;
        private final Method walk;
        private final Function<Stream<?>, Class<?>[]> collect;

        @SuppressWarnings({"unchecked", "rawtypes"})
        StackWalkerWalker() throws Exception {
            Class<?> walkerClass = Class.forName("java.lang.StackWalker");
            Class<? extends Enum> optionClass =
                (Class<? extends Enum>) Class.forName("java.lang.StackWalker$Option");
            Object retain = Enum.valueOf(optionClass, "RETAIN_CLASS_REFERENCE");
            walker = walkerClass.getMethod("getInstance", optionClass).invoke(null, retain);
            walk = walkerClass.getMethod("walk", Function.class);
            final Method declaringClass =
                Class.forName("java.lang.StackWalker$StackFrame").getMethod("getDeclaringClass");
            collect = new Function<Stream<?>, Class<?>[]>() {
                @Override
                public Class<?>[] apply(Stream<?> frames) {
                    Object[] all = frames.toArray();
                    Class<?>[] classes = new Class<?>[all.length];
                    for (int index = 0; index < all.length; index++) {
                        try {
                            classes[index] = (Class<?>) declaringClass.invoke(all[index]);
                        } catch (ReflectiveOperationException ignored) {
                            classes[index] = null;
                        }
                    }
                    return classes;
                }
            };
        }

        @Override
        public Class<?>[] classes() throws Exception {
            return (Class<?>[]) walk.invoke(walker, collect);
        }
    }

    /** Java 8: the protected class context of an uninstalled SecurityManager. */
    @SuppressWarnings("removal")
    private static final class ClassContextWalker extends SecurityManager implements Walker {
        @Override
        public Class<?>[] classes() {
            return getClassContext();
        }
    }
}
