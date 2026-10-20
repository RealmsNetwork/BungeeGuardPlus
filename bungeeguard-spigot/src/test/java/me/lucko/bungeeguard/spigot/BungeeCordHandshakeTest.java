package me.lucko.bungeeguard.spigot;

import me.lucko.bungeeguard.backend.BungeeGuardBackend;
import me.lucko.bungeeguard.backend.TokenStore;
import org.junit.Test;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import static org.junit.Assert.*;

public class BungeeCordHandshakeTest {
    private static final String HOST = "lobby.realmsnetwork.test";
    private static final String IP = "203.0.113.20";
    private static final UUID UUID_VALUE = UUID.fromString("01234567-89ab-cdef-0123-456789abcdef");

    private static TokenStore configuredTokenStore() {
        BungeeGuardBackend backend = new BungeeGuardBackend() {
            @Override public String getKickMessage(String key) { return key; }
            @Override public List<String> getTokens() { return Arrays.asList("configured-token"); }
            @Override public Path getConfigPath() { return Paths.get("target/test-config.yml"); }
            @Override public void reloadConfig() { }
            @Override public boolean isVerbose() { return false; }
        };
        TokenStore tokenStore = new TokenStore(backend);
        tokenStore.load();
        return tokenStore;
    }

    private static TokenStore defaultTokenStore() {
        BungeeGuardBackend backend = new BungeeGuardBackend() {
            @Override public String getKickMessage(String key) { return key; }
            @Override public List<String> getTokens() { return Arrays.asList("YOUR_TOKEN"); }
            @Override public Path getConfigPath() { return Paths.get("target/test-config.yml"); }
            @Override public void reloadConfig() { }
            @Override public boolean isVerbose() { return false; }
        };
        TokenStore tokenStore = new TokenStore(backend);
        tokenStore.load();
        return tokenStore;
    }

    @Test
    public void acceptsCurrentFloodgateMarkerAndDoesNotRequireBungeeGuardToken() {
        String payload = "^Floodgate^>encrypted-bedrock-payload";
        String handshake = String.join("\00", HOST, payload, IP, UUID_VALUE.toString(), "[]");

        BungeeCordHandshake result = BungeeCordHandshake.decodeAndVerify(handshake, configuredTokenStore());

        assertTrue("Floodgate should be accepted by BungeeGuard's token gate", result instanceof BungeeCordHandshake.Success);
        BungeeCordHandshake.Success success = (BungeeCordHandshake.Success) result;
        assertEquals(HOST + "\00" + payload, success.serverHostname());
        assertEquals(IP, success.socketAddressHostname());
        assertEquals(UUID_VALUE, success.uniqueId());
        assertEquals("[]", success.propertiesJson());
    }

    @Test
    public void acceptsOneUseMarkerMintedOnlyAfterFloodgateValidation() {
        String marker = FloodgateHandshakeIntegration.createValidatedMarker();
        String sanitizedHostname = String.join("\00", HOST, IP, UUID_VALUE.toString(), "[]");
        String handshake = FloodgateHandshakeIntegration.insertMarkerAfterHostname(sanitizedHostname, marker);
        assertEquals(String.join("\00", HOST, marker, IP, UUID_VALUE.toString(), "[]"), handshake);

        BungeeCordHandshake result = BungeeCordHandshake.decodeAndVerify(handshake, defaultTokenStore());

        assertTrue("A marker from Floodgate's successful decrypt callback should bypass the Java token gate", result instanceof BungeeCordHandshake.Success);
        BungeeCordHandshake.Success success = (BungeeCordHandshake.Success) result;
        assertEquals("Floodgate's private marker must not reach the server hostname", HOST, success.serverHostname());
        assertEquals(IP, success.socketAddressHostname());
        assertEquals(UUID_VALUE, success.uniqueId());

        BungeeCordHandshake secondAttempt = BungeeCordHandshake.decodeAndVerify(handshake, configuredTokenStore());
        assertTrue("The marker must be single-use", secondAttempt instanceof BungeeCordHandshake.Fail);
    }

    @Test
    public void doesNotAppendValidatedMarkerAfterProperties() {
        String marker = FloodgateHandshakeIntegration.createValidatedMarker();
        String handshake = String.join("\00", HOST, IP, UUID_VALUE.toString(), "[]");

        String marked = FloodgateHandshakeIntegration.insertMarkerAfterHostname(handshake, marker);

        assertEquals(String.join("\00", HOST, marker, IP, UUID_VALUE.toString(), "[]"), marked);
        assertFalse(marked.endsWith(marker));
    }

    @Test
    public void forgedFloodgateIntegrationMarkerDoesNotBypassTokenValidation() {
        String forged = "^RealmsNetworkBungeeGuard^not-a-real-nonce";
        String handshake = String.join("\00", HOST, forged, IP, UUID_VALUE.toString(), "[]");

        BungeeCordHandshake result = BungeeCordHandshake.decodeAndVerify(handshake, configuredTokenStore());

        assertTrue(result instanceof BungeeCordHandshake.Fail);
    }

    @Test
    public void recognizesFloodgateMarkerAfterAdditionalHostnameComponent() {
        String payload = "^Floodgate^>encrypted-bedrock-payload";
        String handshake = String.join("\00", HOST, "education-forwarded-host", payload, IP, UUID_VALUE.toString(), "[]");

        BungeeCordHandshake result = BungeeCordHandshake.decodeAndVerify(handshake, configuredTokenStore());

        assertTrue(result instanceof BungeeCordHandshake.Success);
        BungeeCordHandshake.Success success = (BungeeCordHandshake.Success) result;
        assertEquals(HOST + "\00education-forwarded-host\00" + payload, success.serverHostname());
        assertEquals(IP, success.socketAddressHostname());
    }

    @Test
    public void recognizesFloodgateHandshakeWithoutPropertiesField() {
        String payload = "^Floodgate^>encrypted-bedrock-payload";
        String handshake = String.join("\00", HOST, payload, IP, UUID_VALUE.toString());

        BungeeCordHandshake result = BungeeCordHandshake.decodeAndVerify(handshake, configuredTokenStore());

        assertTrue(result instanceof BungeeCordHandshake.Success);
        assertEquals("[]", ((BungeeCordHandshake.Success) result).propertiesJson());
    }

    @Test
    public void acceptsFloodgateEvenWhenBungeeGuardTokensAreNotConfigured() {
        String payload = "^Floodgate^>encrypted-bedrock-payload";
        String handshake = String.join("\00", HOST, payload, IP, UUID_VALUE.toString(), "[]");

        BungeeCordHandshake result = BungeeCordHandshake.decodeAndVerify(handshake, defaultTokenStore());

        assertTrue(result instanceof BungeeCordHandshake.Success);
    }

    @Test
    public void ordinaryJavaHandshakeStillRejectsUnconfiguredTokens() {
        String handshake = String.join("\00", HOST, IP, UUID_VALUE.toString(), "[]");

        BungeeCordHandshake result = BungeeCordHandshake.decodeAndVerify(handshake, defaultTokenStore());

        assertTrue(result instanceof BungeeCordHandshake.Fail);
        assertEquals(BungeeCordHandshake.Fail.Reason.INCORRECT_TOKEN, ((BungeeCordHandshake.Fail) result).reason());
    }

    @Test
    public void normalHandshakeWithoutTokenIsStillRejected() {
        String handshake = String.join("\00", HOST, IP, UUID_VALUE.toString(), "[]");

        BungeeCordHandshake result = BungeeCordHandshake.decodeAndVerify(handshake, configuredTokenStore());

        assertTrue(result instanceof BungeeCordHandshake.Fail);
        assertEquals(BungeeCordHandshake.Fail.Reason.NO_TOKEN, ((BungeeCordHandshake.Fail) result).reason());
    }

    @Test
    public void normalHandshakeStillRequiresAndRemovesValidToken() {
        String properties = "[{\"name\":\"textures\",\"value\":\"skin-value\"},{\"name\":\"bungeeguard-token\",\"value\":\"configured-token\"}]";
        String handshake = String.join("\00", HOST, IP, UUID_VALUE.toString(), properties);

        BungeeCordHandshake result = BungeeCordHandshake.decodeAndVerify(handshake, configuredTokenStore());

        assertTrue(result instanceof BungeeCordHandshake.Success);
        assertFalse(((BungeeCordHandshake.Success) result).propertiesJson().contains("bungeeguard-token"));
        assertTrue(((BungeeCordHandshake.Success) result).propertiesJson().contains("textures"));
    }
}
