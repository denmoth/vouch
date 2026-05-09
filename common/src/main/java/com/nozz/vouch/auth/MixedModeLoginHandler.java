package com.nozz.vouch.auth;

import com.nozz.vouch.VouchMod;
import com.nozz.vouch.util.PremiumVerifier;
import com.mojang.authlib.GameProfile;
import net.minecraft.network.ClientConnection;
import net.minecraft.network.encryption.NetworkEncryptionException;
import net.minecraft.network.encryption.NetworkEncryptionUtils;
import net.minecraft.network.packet.c2s.login.LoginKeyC2SPacket;
import net.minecraft.network.packet.s2c.login.LoginHelloS2CPacket;
import net.minecraft.text.Text;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.net.SocketAddress;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Handles the mixed online/offline mode login flow.
 * 
 * When premium_auto_login is enabled on an offline-mode server, this class
 * manages per-connection encryption handshake state. Premium players go through
 * the standard Mojang encryption + session verification, while non-premium
 * players continue through the normal offline login flow.
 */
public final class MixedModeLoginHandler {
    private static final Logger LOGGER = LoggerFactory.getLogger("Vouch/MixedModeLogin");

    private static MixedModeLoginHandler instance;

    private final Map<SocketAddress, PendingVerification> pendingVerifications = new ConcurrentHashMap<>();

    private MixedModeLoginHandler() {
    }

    public static MixedModeLoginHandler getInstance() {
        if (instance == null) {
            instance = new MixedModeLoginHandler();
        }
        return instance;
    }

    /**
     * Initiate the premium verification flow by sending an encryption request.
     *
     * @param connection The client connection
     * @param username   The player's username from LoginHelloC2SPacket
     * @param keyPair    The server's RSA key pair
     */
    public void initiatePremiumVerification(ClientConnection connection, String username, KeyPair keyPair) {
        byte[] nonce = new byte[4];
        new java.security.SecureRandom().nextBytes(nonce);

        String serverId = Long.toHexString(new java.security.SecureRandom().nextLong());

        PendingVerification pending = new PendingVerification(username, serverId, nonce, keyPair);
        pendingVerifications.put(connection.getAddress(), pending);

        // Send the encryption request packet to the client
        connection.send(new LoginHelloS2CPacket(serverId, keyPair.getPublic().getEncoded(), nonce, true));

        LOGGER.debug("Sent encryption request to {} for premium verification", username);
    }

    /**
     * Handle the encryption response from a client during mixed-mode login.
     * Decrypts the shared secret, computes the server hash, and verifies
     * the player's session with the Mojang session server.
     *
     * @param connection The client connection
     * @param packet     The encryption response packet
     * @return Optional containing the authenticated GameProfile if verification succeeds
     */
    public Optional<GameProfile> handleEncryptionResponse(ClientConnection connection, LoginKeyC2SPacket packet) {
        SocketAddress address = connection.getAddress();
        PendingVerification pending = pendingVerifications.remove(address);

        if (pending == null) {
            LOGGER.warn("Received encryption response from {} but no pending verification found", address);
            return Optional.empty();
        }

        try {
            PrivateKey privateKey = pending.keyPair().getPrivate();

            // Verify and decrypt the nonce to ensure it matches what we sent
            if (!packet.verifySignedNonce(pending.nonce(), privateKey)) {
                LOGGER.warn("Nonce verification failed for {}", pending.username());
                return Optional.empty();
            }

            // Decrypt the shared secret
            SecretKey sharedSecret = packet.decryptSecretKey(privateKey);

            // Compute the Minecraft-style server hash
            String serverHash = computeServerIdHash(
                    pending.serverId(),
                    sharedSecret,
                    pending.keyPair().getPublic()
            );

            // Verify with Mojang session server
            Optional<GameProfile> profile = PremiumVerifier.getInstance()
                    .verifySession(pending.username(), serverHash)
                    .join(); // blocking here is OK — we're in the netty thread handling the login packet

            if (profile.isPresent()) {
                LOGGER.info("Premium verification successful for {} (UUID: {})",
                        profile.get().getName(), profile.get().getId());

                // Enable encryption on the connection
                Cipher decryptCipher = NetworkEncryptionUtils.cipherFromKey(Cipher.DECRYPT_MODE, sharedSecret);
                Cipher encryptCipher = NetworkEncryptionUtils.cipherFromKey(Cipher.ENCRYPT_MODE, sharedSecret);
                connection.setupEncryption(decryptCipher, encryptCipher);
            } else {
                LOGGER.debug("Premium session verification failed for {}", pending.username());
            }

            return profile;

        } catch (NetworkEncryptionException e) {
            LOGGER.error("Encryption error during premium verification for {}: {}", pending.username(), e.getMessage());
            return Optional.empty();
        }
    }

    /**
     * Check if there's a pending premium verification for this connection.
     */
    public boolean hasPendingVerification(ClientConnection connection) {
        return pendingVerifications.containsKey(connection.getAddress());
    }

    /**
     * Clean up pending verification state for a connection.
     */
    public void cleanup(ClientConnection connection) {
        pendingVerifications.remove(connection.getAddress());
    }

    /**
     * Compute the Minecraft server ID hash.
     *
     * Minecraft uses a special SHA-1 digest format:
     * SHA1(serverId bytes + sharedSecret bytes + publicKey bytes)
     * then interprets the result as a signed big-endian integer
     * and converts to a lowercase hex string (twos-complement, no zero-padding).
     */
    private static String computeServerIdHash(String serverId, SecretKey sharedSecret, java.security.PublicKey publicKey) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-1");
            digest.update(serverId.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1));
            digest.update(sharedSecret.getEncoded());
            digest.update(publicKey.getEncoded());
            return new BigInteger(digest.digest()).toString(16);
        } catch (Exception e) {
            throw new RuntimeException("Failed to compute server ID hash", e);
        }
    }

    /**
     * Immutable record for tracking a pending premium verification.
     */
    private record PendingVerification(
            String username,
            String serverId,
            byte[] nonce,
            KeyPair keyPair
    ) {
    }
}
