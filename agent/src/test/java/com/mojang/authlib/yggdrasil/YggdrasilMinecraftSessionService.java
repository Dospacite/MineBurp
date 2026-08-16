package com.mojang.authlib.yggdrasil;

import java.util.UUID;

import com.mojang.authlib.GameProfile;

/**
 * A binary-compatible stand-in for Authlib's session service.
 *
 * <p>Both overloads branch on purpose. javac emits a StackMapTable for them,
 * which is what the real Authlib class carries; a straight-line body let a
 * transformer that could not handle compressed frames pass this test while
 * failing against every shipped Authlib.
 */
public final class YggdrasilMinecraftSessionService {
    public static int originalCalls;

    public void joinServer(GameProfile profile, String accessToken, String serverHash) {
        if (profile == null || accessToken == null || serverHash == null) {
            throw new IllegalArgumentException("join arguments must be present");
        }
        for (int attempt = 0; attempt < 2; attempt++) {
            if (attempt > 0) {
                originalCalls++;
            }
        }
    }

    public void joinServer(UUID profileId, String accessToken, String serverHash) {
        if (profileId == null || accessToken == null || serverHash == null) {
            throw new IllegalArgumentException("join arguments must be present");
        }
        for (int attempt = 0; attempt < 2; attempt++) {
            if (attempt > 0) {
                originalCalls++;
            }
        }
    }
}
