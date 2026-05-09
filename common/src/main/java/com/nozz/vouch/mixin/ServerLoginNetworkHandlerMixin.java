package com.nozz.vouch.mixin;

import com.mojang.authlib.GameProfile;
import com.nozz.vouch.auth.MixedModeLoginHandler;
import com.nozz.vouch.config.VouchConfigManager;
import com.nozz.vouch.db.DatabaseManager;
import com.nozz.vouch.db.PremiumOverrideStatus;
import com.nozz.vouch.util.PremiumVerifier;
import net.minecraft.network.ClientConnection;
import net.minecraft.network.packet.c2s.login.LoginHelloC2SPacket;
import net.minecraft.network.packet.c2s.login.LoginKeyC2SPacket;
import net.minecraft.network.packet.s2c.login.LoginHelloS2CPacket;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.network.ServerLoginNetworkHandler;
import net.minecraft.text.Text;
import net.minecraft.util.Uuids;
import org.slf4j.Logger;
import org.spongepowered.asm.mixin.Final;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Shadow;
import org.spongepowered.asm.mixin.Unique;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

import java.util.Optional;

/**
 * Mixin for mixed online/offline mode (premium auto-login).
 *
 * On offline-mode servers with premium_auto_login enabled, this intercepts
 * the login handshake to selectively force encryption for players whose
 * usernames exist in the Mojang API. This provides cryptographic proof
 * of account ownership and assigns the correct online UUID to premium players.
 *
 * Non-premium players continue through the normal offline login flow.
 */
@Mixin(ServerLoginNetworkHandler.class)
public abstract class ServerLoginNetworkHandlerMixin {

    @Shadow
    @Final
    MinecraftServer server;

    @Shadow
    @Final
    ClientConnection connection;

    @Shadow
    String profileName;

    @Shadow
    abstract void startVerify(GameProfile profile);

    @Shadow
    @Final
    static Logger LOGGER;

    /**
     * Whether this specific connection was forced into encryption by Vouch's
     * mixed-mode login. Used to distinguish from vanilla online-mode encryption.
     */
    @Unique
    private boolean vouch$forcedEncryption = false;

    /**
     * Intercept the login hello packet on offline-mode servers.
     * If premium_auto_login is enabled, check the Mojang API for the username.
     * If the username belongs to a premium account AND the player is not marked
     * as forced-offline in DB, initiate encryption handshake.
     */
    @Inject(method = "onHello", at = @At("HEAD"), cancellable = true)
    private void vouch$onHello(LoginHelloC2SPacket packet, CallbackInfo ci) {
        // Only act on offline-mode servers with premium auto-login enabled
        if (server.isOnlineMode()) {
            return;
        }

        VouchConfigManager config;
        try {
            config = VouchConfigManager.getInstance();
        } catch (IllegalStateException e) {
            // Config not initialized yet
            return;
        }

        if (!config.isPremiumAutoLogin()) {
            return;
        }

        String username = packet.name();

        // Validate username
        if (username == null || !username.matches("[a-zA-Z0-9_]{3,16}")) {
            return;
        }

        // Cancel vanilla flow — we'll handle it asynchronously
        ci.cancel();

        // Store the profile name as vanilla would
        this.profileName = username;

        // Check the player's premium override status in the database
        DatabaseManager.getInstance().getPremiumOverrideStatus(username).thenCompose(status -> {
            if (status == PremiumOverrideStatus.FORCED_OFFLINE) {
                LOGGER.debug("Player {} is forced-offline by admin, skipping premium check", username);
                return java.util.concurrent.CompletableFuture.completedFuture(false);
            } else if (status == PremiumOverrideStatus.MARKED_ONLINE) {
                LOGGER.debug("Player {} is marked-online, will send encryption challenge", username);
                return java.util.concurrent.CompletableFuture.completedFuture(true);
            } else {
                // NO_OVERRIDE — check config
                if (config.isPremiumOfflineByDefault()) {
                    LOGGER.debug("Player {} has no override and offline-by-default is enabled, treating as offline", username);
                    return java.util.concurrent.CompletableFuture.completedFuture(false);
                }
                // offline-by-default is disabled — check Mojang API
                return PremiumVerifier.getInstance().usernameExistsInMojangAPI(username);
            }
        }).thenAccept(isPremium -> {
            server.execute(() -> {
                if (!connection.isOpen()) {
                    return;
                }

                if (isPremium) {
                    // Premium username found — initiate encryption handshake
                    LOGGER.info("Username {} is premium, initiating encryption for mixed-mode login", username);
                    vouch$forcedEncryption = true;
                    MixedModeLoginHandler.getInstance().initiatePremiumVerification(
                            connection, username, server.getKeyPair());
                } else {
                    // Not premium or forced offline — proceed with normal offline login
                    LOGGER.debug("Username {} is not premium, proceeding with offline login", username);
                    GameProfile offlineProfile = Uuids.getOfflinePlayerProfile(username);
                    startVerify(offlineProfile);
                }
            });
        }).exceptionally(throwable -> {
            // On any error, fall back to offline login
            LOGGER.warn("Error during premium check for {}, falling back to offline login: {}",
                    username, throwable.getMessage());
            server.execute(() -> {
                if (connection.isOpen()) {
                    GameProfile offlineProfile = Uuids.getOfflinePlayerProfile(username);
                    startVerify(offlineProfile);
                }
            });
            return null;
        });
    }

    /**
     * Intercept the encryption response on connections where Vouch
     * forced encryption for premium verification on an offline-mode server.
     */
    @Inject(method = "onKey", at = @At("HEAD"), cancellable = true)
    private void vouch$onKey(LoginKeyC2SPacket packet, CallbackInfo ci) {
        if (!vouch$forcedEncryption) {
            return;
        }

        // Cancel vanilla handler — we handle it ourselves
        ci.cancel();

        MixedModeLoginHandler handler = MixedModeLoginHandler.getInstance();

        Optional<GameProfile> result = handler.handleEncryptionResponse(connection, packet);

        if (result.isPresent()) {
            GameProfile authenticatedProfile = result.get();
            LOGGER.info("Premium auto-login: {} verified as {} (UUID: {})",
                    profileName, authenticatedProfile.getName(), authenticatedProfile.getId());
            startVerify(authenticatedProfile);
        } else {
            // Encryption verification failed — disconnect
            LOGGER.warn("Premium verification failed for {}, disconnecting", profileName);
            ServerLoginNetworkHandler self = (ServerLoginNetworkHandler) (Object) this;
            self.disconnect(Text.literal("Authentication failed. Please try again."));
        }

        vouch$forcedEncryption = false;
    }
}
