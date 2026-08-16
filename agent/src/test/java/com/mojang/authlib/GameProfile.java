package com.mojang.authlib;

import java.util.UUID;

public final class GameProfile {
    private final UUID id;

    public GameProfile(UUID id) {
        this.id = id;
    }

    public UUID getId() {
        return id;
    }
}
