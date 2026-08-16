package tools.mineburp.agent;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

/** Short-lived reference to the session already supplied to Minecraft. */
final class SessionCredential {
    private Object sessionService;
    private Object identity;
    private String accessToken;
    private final long createdAtMillis;

    SessionCredential(Object sessionService, Object identity, String accessToken) {
        this.sessionService = sessionService;
        this.identity = identity;
        this.accessToken = accessToken;
        this.createdAtMillis = System.currentTimeMillis();
    }

    boolean expired(long nowMillis) {
        return nowMillis - createdAtMillis > 60_000L;
    }

    void invoke(String upstreamHash) throws Exception {
        Object service = sessionService;
        Object currentIdentity = identity;
        String token = accessToken;
        if (service == null || currentIdentity == null || token == null) {
            throw new IllegalStateException("the captured session is no longer available");
        }
        Method join = findJoinMethod(service.getClass(), currentIdentity.getClass());
        try {
            join.invoke(service, currentIdentity, token, upstreamHash);
        } catch (InvocationTargetException error) {
            Throwable cause = error.getCause();
            if (cause instanceof Exception) {
                throw (Exception) cause;
            }
            throw error;
        }
    }

    void clear() {
        sessionService = null;
        identity = null;
        accessToken = null;
    }

    private static Method findJoinMethod(Class<?> serviceType, Class<?> identityType)
        throws NoSuchMethodException {
        for (Method method : serviceType.getMethods()) {
            Class<?>[] parameters = method.getParameterTypes();
            if (method.getName().equals("joinServer")
                && parameters.length == 3
                && parameters[0].isAssignableFrom(identityType)
                && parameters[1] == String.class
                && parameters[2] == String.class) {
                return method;
            }
        }
        throw new NoSuchMethodException("Authlib joinServer method was not found");
    }
}
