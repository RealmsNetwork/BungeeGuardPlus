/*
 * This file is part of BungeeGuard, licensed under the MIT License.
 *
 *  Copyright (c) lucko (Luck) <luck@lucko.me>
 *  Copyright (c) contributors
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in all
 *  copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *  SOFTWARE.
 */

package me.lucko.bungeeguard.spigot;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.reflect.TypeToken;
import me.lucko.bungeeguard.backend.TokenStore;

import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Encapsulates a BungeeCord "ip forwarding" handshake result.
 */
public class BungeeCordHandshake {

    /** The name of the BungeeGuard auth token. */
    private static final String BUNGEEGUARD_TOKEN_NAME = "bungeeguard-token";
    /** The key used to define the name of properties in the handshake. */
    private static final String PROPERTY_NAME_KEY = "name";
    /** The key used to define the value of properties in the handshake. */
    private static final String PROPERTY_VALUE_KEY = "value";
    /** The maximum allowed length of the handshake. */
    private static final int HANDSHAKE_LENGTH_LIMIT = 5_000;

    /** Shared Gson instance. */
    private static final Gson GSON = new Gson();
    /** The type of the property list in the handshake. */
    private static final Type PROPERTY_LIST_TYPE = new TypeToken<List<JsonObject>>(){}.getType();

    /**
     * Decodes a BungeeCord handshake, additionally ensuring it contains a
     * BungeeGuard token allowed by the {@link TokenStore}.
     *
     * @param handshake the handshake data
     * @param tokenStore the token store
     * @return the handshake result
     */
    public static BungeeCordHandshake decodeAndVerify(String handshake, TokenStore tokenStore) {
        try {
            return decodeAndVerify0(handshake, tokenStore);
        } catch (Exception e) {
            new Exception("Failed to decode handshake", e).printStackTrace();
            return new Fail(Fail.Reason.INVALID_HANDSHAKE, encodeBase64(handshake));
        }
    }

    private static BungeeCordHandshake decodeAndVerify0(String handshake, TokenStore tokenStore) throws Exception {
        if (handshake.length() > HANDSHAKE_LENGTH_LIMIT) {
            return new Fail(Fail.Reason.INVALID_HANDSHAKE, "handshake length " + handshake.length() + " is > " + HANDSHAKE_LENGTH_LIMIT);
        }

        // BungeeCord forwards the hostname, client address, UUID, and (usually) a JSON
        // properties array separated by NUL characters. Floodgate inserts its encrypted
        // payload into the hostname. Do not assume that the handshake has exactly five
        // fields: extra hostname components and omitted empty trailing fields are possible.
        String[] split = handshake.split("\00");
        boolean hasProperties = split.length >= 4 && isPropertiesArray(split[split.length - 1]);
        int socketAddressIndex = split.length - (hasProperties ? 3 : 2);
        int validatedFloodgateMarkerIndex = findValidatedFloodgateMarkerIndex(split, socketAddressIndex);
        boolean hasValidatedFloodgateMarker = validatedFloodgateMarkerIndex >= 1
                && FloodgateHandshakeIntegration.consumeValidatedMarker(split[validatedFloodgateMarkerIndex]);

        // Never bypass Java token validation based only on a client-supplied ^Floodgate^ string.
        // The encrypted marker is normally consumed by Floodgate before this listener runs; our
        // private marker is the only bypass accepted here because it was minted after validation.
        if (hasValidatedFloodgateMarker) {
            int uuidIndex = hasProperties ? split.length - 2 : split.length - 1;
            if (socketAddressIndex < 1 || uuidIndex <= socketAddressIndex) {
                return new Fail(Fail.Reason.INVALID_HANDSHAKE, encodeBase64(handshake));
            }

            List<String> hostnameComponents = new ArrayList<>();
            for (int i = 0; i < socketAddressIndex; i++) {
                // Floodgate's backend handler consumes the encrypted payload before Paper's
                // PlayerHandshakeEvent fires. Our one-use marker bridges that lifecycle gap;
                // strip it so it never reaches the actual Minecraft server hostname.
                if (hasValidatedFloodgateMarker && i == validatedFloodgateMarkerIndex) {
                    continue;
                }
                hostnameComponents.add(split[i]);
            }
            String serverHostname = String.join("\00", hostnameComponents);
            String socketAddressHostname = split[socketAddressIndex];
            UUID uniqueId;
            try {
                uniqueId = UUID.fromString(split[uuidIndex].replaceFirst("(\\w{8})(\\w{4})(\\w{4})(\\w{4})(\\w{12})", "$1-$2-$3-$4-$5"));
            } catch (Exception e) {
                return new Fail(Fail.Reason.INVALID_UNIQUE_ID, encodeBase64(handshake));
            }

            String connectionDescription = uniqueId + " @ " + encodeBase64(socketAddressHostname);
            List<JsonObject> properties = new LinkedList<>();
            if (hasProperties) {
                List<JsonObject> decodedProperties = GSON.fromJson(split[split.length - 1], PROPERTY_LIST_TYPE);
                if (decodedProperties == null) {
                    return new Fail(Fail.Reason.INVALID_HANDSHAKE, connectionDescription);
                }
                properties.addAll(decodedProperties);
            }

            // Floodgate authenticates its own encrypted forwarding payload with its
            // configured key on the backend. A separate BungeeGuard token is therefore
            // not required for a recognized Floodgate handshake. Remove any BungeeGuard
            // property before forwarding the handshake, so the secret cannot leak.
            properties.removeIf(property ->
                    property != null
                            && property.has(PROPERTY_NAME_KEY)
                            && property.get(PROPERTY_NAME_KEY).isJsonPrimitive()
                            && BUNGEEGUARD_TOKEN_NAME.equals(property.get(PROPERTY_NAME_KEY).getAsString()));

            return new Success(serverHostname, socketAddressHostname, uniqueId,
                    GSON.toJson(properties, PROPERTY_LIST_TYPE));
        }

        if (split.length != 3 && split.length != 4) {
            return new Fail(Fail.Reason.INVALID_HANDSHAKE, encodeBase64(handshake));
        }

        // Keep the normal BungeeCord handshake path strict. Ordinary Java clients still
        // need an allowed BungeeGuard token even when their handshake has extra properties.
        if (tokenStore.isUsingDefaultConfig()) {
            return new Fail(Fail.Reason.INCORRECT_TOKEN, "Allowed tokens have not been configured! Please refer to https://github.com/lucko/BungeeGuard/blob/master/INSTALLATION.md for help.");
        }

        int readIndex = 1;
        String serverHostname = split[0];
        String socketAddressHostname = split[readIndex++];
        UUID uniqueId;
        try {
            uniqueId = UUID.fromString(split[readIndex++].replaceFirst("(\\w{8})(\\w{4})(\\w{4})(\\w{4})(\\w{12})", "$1-$2-$3-$4-$5"));
        } catch (Exception e) {
            return new Fail(Fail.Reason.INVALID_UNIQUE_ID, encodeBase64(handshake));
        }

        String connectionDescription = uniqueId + " @ " + encodeBase64(socketAddressHostname);

        if (split.length == 3) {
            return new Fail(Fail.Reason.NO_TOKEN, connectionDescription);
        }

        List<JsonObject> properties = new LinkedList<>(GSON.fromJson(split[readIndex], PROPERTY_LIST_TYPE));
        if (properties.isEmpty()) {
            return new Fail(Fail.Reason.NO_TOKEN, connectionDescription);
        }

        String bungeeGuardToken = null;
        for (Iterator<JsonObject> iterator = properties.iterator(); iterator.hasNext(); ) {
            JsonObject property = iterator.next();
            if (property.get(PROPERTY_NAME_KEY).getAsString().equals(BUNGEEGUARD_TOKEN_NAME)) {
                if (bungeeGuardToken != null) {
                    return new Fail(Fail.Reason.DUPLICATED_TOKEN, connectionDescription);
                }

                bungeeGuardToken = property.get(PROPERTY_VALUE_KEY).getAsString();
                iterator.remove();
            }
        }

        if (bungeeGuardToken == null) {
            return new Fail(Fail.Reason.NO_TOKEN, connectionDescription);
        }

        if (!tokenStore.isAllowed(bungeeGuardToken)) {
            return new Fail(Fail.Reason.INCORRECT_TOKEN, connectionDescription + " - " + encodeBase64(bungeeGuardToken));
        }

        String newPropertiesString = GSON.toJson(properties, PROPERTY_LIST_TYPE);
        return new Success(serverHostname, socketAddressHostname, uniqueId, newPropertiesString);
    }

    private static int findValidatedFloodgateMarkerIndex(String[] split, int socketAddressIndex) {
        if (socketAddressIndex <= 1) {
            return -1;
        }
        for (int i = 1; i < socketAddressIndex; i++) {
            if (FloodgateHandshakeIntegration.isValidatedMarkerCandidate(split[i])) {
                return i;
            }
        }
        return -1;
    }

    private static boolean isPropertiesArray(String value) {
        String trimmed = value.trim();
        return trimmed.startsWith("[") && trimmed.endsWith("]");
    }

    public static String encodeBase64(String s) {
        return Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Encapsulates a successful handshake.
     */
    public static final class Success extends BungeeCordHandshake {
        private final String serverHostname;
        private final String socketAddressHostname;
        private final UUID uniqueId;
        private final String propertiesJson;

        Success(String serverHostname, String socketAddressHostname, UUID uniqueId, String propertiesJson) {
            this.serverHostname = serverHostname;
            this.socketAddressHostname = socketAddressHostname;
            this.uniqueId = uniqueId;
            this.propertiesJson = propertiesJson;
        }

        public String serverHostname() {
            return this.serverHostname;
        }

        public String socketAddressHostname() {
            return this.socketAddressHostname;
        }

        public UUID uniqueId() {
            return this.uniqueId;
        }

        public String propertiesJson() {
            return this.propertiesJson;
        }

        /**
         * Re-encodes this handshake to the format used by BungeeCord.
         *
         * @return an encoded string for the handshake
         */
        public String encode() {
            return this.serverHostname + "\00" + this.socketAddressHostname + "\00" + this.uniqueId + "\00" + this.propertiesJson;
        }
    }

    /**
     * Encapsulates an unsuccessful handshake.
     */
    public static final class Fail extends BungeeCordHandshake {
        private final Reason reason;
        private final String connectionDescription;

        Fail(Reason reason, String connectionDescription) {
            this.reason = reason;
            this.connectionDescription = connectionDescription;
        }

        public Reason reason() {
            return this.reason;
        }

        public String describeConnection() {
            return this.connectionDescription;
        }

        public enum Reason {
            INVALID_HANDSHAKE, INVALID_UNIQUE_ID, NO_TOKEN, DUPLICATED_TOKEN, INCORRECT_TOKEN
        }
    }
}
