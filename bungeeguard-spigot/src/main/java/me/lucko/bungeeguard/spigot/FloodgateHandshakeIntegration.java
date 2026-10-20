/*
 * This file is part of BungeeGuard+, licensed under the MIT License.
 */
package me.lucko.bungeeguard.spigot;

import org.bukkit.Bukkit;
import org.bukkit.plugin.Plugin;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.security.SecureRandom;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Bridges Floodgate's successful, per-connection encrypted-handshake validation to Paper's
 * PlayerHandshakeEvent. Floodgate removes its encrypted payload before Paper emits that event,
 * so BungeeGuard cannot safely infer validation merely from the now-missing hostname marker.
 *
 * A one-use, unpredictable marker is appended only from Floodgate's own HandshakeHandler callback
 * after Floodgate has decrypted and validated the payload. BungeeGuard consumes the marker once
 * and removes it from the forwarded hostname. Without the Floodgate callback, a spoofed marker
 * cannot pass the token gate.
 */
public final class FloodgateHandshakeIntegration {
    private static final String MARKER_PREFIX = "^RealmsNetworkBungeeGuard^";
    private static final long MARKER_TTL_MILLIS = 10_000L;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Map<String, Long> PENDING_MARKERS = new ConcurrentHashMap<>();

    private static Object floodgateHandlers;
    private static int handlerId = -1;

    private FloodgateHandshakeIntegration() {
    }

    /**
     * Detect Floodgate / EduFloodgate without assuming the plugin's declared casing or name.
     * The API class is the strongest signal; the name check also lets the enable-event listener
     * recognize the plugin before testing whether its API has finished initializing.
     */
    public static boolean isFloodgatePlugin(Plugin candidate) {
        if (candidate == null) {
            return false;
        }
        String name = candidate.getDescription().getName();
        if (name != null && name.toLowerCase(Locale.ROOT).contains("floodgate")) {
            return true;
        }
        try {
            candidate.getClass().getClassLoader().loadClass("org.geysermc.floodgate.api.InstanceHolder");
            return true;
        } catch (ClassNotFoundException | LinkageError ignored) {
            return false;
        }
    }

    /** Register Floodgate's callback if a compatible, enabled instance is already available. */
    public static synchronized boolean register(Logger logger) {
        for (Plugin candidate : Bukkit.getPluginManager().getPlugins()) {
            if (candidate.isEnabled() && isFloodgatePlugin(candidate)) {
                return register(candidate, logger);
            }
        }
        return false;
    }

    /** Register a callback against the exact Floodgate plugin that has just enabled. */
    public static synchronized boolean register(Plugin floodgate, Logger logger) {
        if (floodgate == null || !floodgate.isEnabled() || !isFloodgatePlugin(floodgate)) {
            return false;
        }
        if (handlerId >= 0) {
            return true;
        }

        try {
            ClassLoader loader = floodgate.getClass().getClassLoader();
            Class<?> handlerType = loader.loadClass("org.geysermc.floodgate.api.handshake.HandshakeHandler");
            Class<?> instanceHolderType = loader.loadClass("org.geysermc.floodgate.api.InstanceHolder");
            Object handlers = instanceHolderType.getMethod("getHandshakeHandlers").invoke(null);
            if (handlers == null) {
                logger.warning("Floodgate is present, but its handshake API is not initialized; Bedrock/Education bypass is unavailable.");
                return false;
            }

            InvocationHandler callback = (proxy, method, args) -> {
                if ("handle".equals(method.getName()) && args != null && args.length == 1 && args[0] != null) {
                    handleValidatedFloodgateHandshake(args[0], logger);
                } else if (method.getDeclaringClass() == Object.class) {
                    if ("toString".equals(method.getName())) return "BungeeGuardFloodgateHandshakeHandler";
                    if ("hashCode".equals(method.getName())) return System.identityHashCode(proxy);
                    if ("equals".equals(method.getName())) return proxy == args[0];
                }
                return null;
            };

            Object adapter = Proxy.newProxyInstance(loader, new Class<?>[]{handlerType}, callback);
            Method addHandler = handlers.getClass().getMethod("addHandshakeHandler", handlerType);
            Object id = addHandler.invoke(handlers, adapter);
            if (!(id instanceof Number) || ((Number) id).intValue() < 0) {
                logger.warning("Could not register with Floodgate's handshake API; Bedrock/Education bypass is unavailable.");
                return false;
            }
            floodgateHandlers = handlers;
            handlerId = ((Number) id).intValue();
            logger.info("Floodgate handshake integration enabled; its encrypted validation remains authoritative for Bedrock/Education connections.");
            return true;
        } catch (ReflectiveOperationException | LinkageError ex) {
            logger.log(Level.WARNING, "Floodgate is present, but its handshake API could not be connected; Bedrock/Education bypass is unavailable.", ex);
            return false;
        }
    }

    private static void handleValidatedFloodgateHandshake(Object data, Logger logger) {
        try {
            boolean isFloodgatePlayer = Boolean.TRUE.equals(data.getClass().getMethod("isFloodgatePlayer").invoke(data));
            if (!isFloodgatePlayer || !hasExpectedFloodgateDataLength(data)) {
                // Floodgate also calls custom handlers for decrypt / malformed-data failures.
                // Only valid payload lengths may mint a BungeeGuard bypass marker.
                return;
            }

            Method getHostname = data.getClass().getMethod("getHostname");
            Method setHostname = data.getClass().getMethod("setHostname", String.class);
            String hostname = (String) getHostname.invoke(data);
            if (hostname == null || hostname.contains(MARKER_PREFIX)) {
                return;
            }

            String marker = createValidatedMarker();
            String markedHostname = insertMarkerAfterHostname(hostname, marker);
            if (markedHostname == null) {
                PENDING_MARKERS.remove(marker);
                logger.warning("Floodgate validated a player, but its sanitized handshake had no forwarding separator; unable to add the BungeeGuard marker.");
                return;
            }
            try {
                // Insert after the first (server hostname) component. Floodgate's callback
                // receives the whole sanitized handshake host, including the proxy-forwarded
                // address, UUID, and properties. Appending would put the marker after the
                // properties array, where BungeeGuard's handshake parser cannot find it.
                setHostname.invoke(data, markedHostname);
            } catch (ReflectiveOperationException | RuntimeException ex) {
                PENDING_MARKERS.remove(marker);
                throw ex;
            }
        } catch (ReflectiveOperationException | RuntimeException ex) {
            logger.log(Level.WARNING, "Could not mark a Floodgate-validated handshake for BungeeGuard; the connection may still require a BungeeGuard token.", ex);
        }
    }

    private static boolean hasExpectedFloodgateDataLength(Object handshakeData) throws ReflectiveOperationException {
        Object bedrockData = handshakeData.getClass().getMethod("getBedrockData").invoke(handshakeData);
        if (bedrockData == null) {
            return false;
        }

        Method getDataLength = bedrockData.getClass().getMethod("getDataLength");
        int actualLength = ((Number) getDataLength.invoke(bedrockData)).intValue();

        // EXPECTED_LENGTH is an implementation constant in Floodgate's BedrockData class rather
        // than part of the public API. Read it reflectively to avoid a compile-time dependency;
        // fail closed if a future Floodgate version removes or changes this validation contract.
        Field expectedLengthField = bedrockData.getClass().getDeclaredField("EXPECTED_LENGTH");
        expectedLengthField.setAccessible(true);
        int expectedLength = expectedLengthField.getInt(null);
        return actualLength == expectedLength;
    }

    static String insertMarkerAfterHostname(String hostname, String marker) {
        if (hostname == null || marker == null) {
            return null;
        }
        int separator = hostname.indexOf('\0');
        if (separator < 0) {
            return null;
        }
        return hostname.substring(0, separator) + '\0' + marker + hostname.substring(separator);
    }

    static String createValidatedMarker() {
        long now = System.currentTimeMillis();
        PENDING_MARKERS.entrySet().removeIf(entry -> entry.getValue() < now);

        byte[] nonce = new byte[24];
        RANDOM.nextBytes(nonce);
        StringBuilder hex = new StringBuilder(nonce.length * 2);
        for (byte b : nonce) {
            hex.append(Character.forDigit((b >>> 4) & 0xF, 16));
            hex.append(Character.forDigit(b & 0xF, 16));
        }
        String marker = MARKER_PREFIX + hex;
        PENDING_MARKERS.put(marker, now + MARKER_TTL_MILLIS);
        return marker;
    }

    static boolean isValidatedMarkerCandidate(String value) {
        return value != null && value.startsWith(MARKER_PREFIX) && value.length() > MARKER_PREFIX.length();
    }

    static boolean consumeValidatedMarker(String marker) {
        if (!isValidatedMarkerCandidate(marker)) {
            return false;
        }
        Long expiresAt = PENDING_MARKERS.remove(marker);
        return expiresAt != null && expiresAt >= System.currentTimeMillis();
    }

    public static synchronized void unregister() {
        if (floodgateHandlers != null && handlerId >= 0) {
            try {
                floodgateHandlers.getClass().getMethod("removeHandshakeHandler", int.class).invoke(floodgateHandlers, handlerId);
            } catch (ReflectiveOperationException ignored) {
                // Floodgate may already be shutting down. This integration is optional.
            }
        }
        floodgateHandlers = null;
        handlerId = -1;
        PENDING_MARKERS.clear();
    }
}
