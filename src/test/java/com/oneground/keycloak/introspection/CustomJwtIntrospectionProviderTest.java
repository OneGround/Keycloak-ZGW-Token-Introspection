package com.oneground.keycloak.introspection;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RealmModel;
import org.keycloak.util.JsonSerialization;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class CustomJwtIntrospectionProviderTest {

    private static final String CLIENT_ID = "test-client";
    private static final String SECRET = "test-secret-at-least-32-bytes-long!!";
    private static final String MAPPED_RSIN = "000000001";
    private static final String OTHER_RSIN = "000000002";

    private RealmModel realm;
    private ClientModel client;
    private ProtocolMapperModel rsinMapper;
    private CustomJwtIntrospectionProvider provider;

    @BeforeEach
    void setUp() {
        KeycloakSession session = mock(KeycloakSession.class);
        KeycloakContext context = mock(KeycloakContext.class);
        realm = mock(RealmModel.class);
        client = mock(ClientModel.class);

        when(session.getContext()).thenReturn(context);
        when(context.getRealm()).thenReturn(realm);
        when(realm.isEnabled()).thenReturn(true);
        when(realm.getClientByClientId(CLIENT_ID)).thenReturn(client);
        when(client.getClientId()).thenReturn(CLIENT_ID);
        when(client.isEnabled()).thenReturn(true);
        when(client.getSecret()).thenReturn(SECRET);

        rsinMapper = hardcodedClaimMapper("rsin", MAPPED_RSIN);
        withMappers(rsinMapper);

        provider = new CustomJwtIntrospectionProvider(session);
    }

    @Test
    void mappedEnabledClientIsActiveWithMapperRsin() {
        Map<String, Object> result = introspect(claims(now()));

        assertEquals(true, result.get("active"));
        assertEquals(MAPPED_RSIN, result.get("rsin"));
    }

    @Test
    void tokenWithoutExpIsStillActive() {
        Map<String, Object> claims = claims(now());
        claims.remove("exp");

        assertEquals(true, introspect(claims).get("active"));
    }

    @Test
    void disabledClientIsInactive() {
        when(client.isEnabled()).thenReturn(false);

        assertInactive(introspect(claims(now())));
    }

    @Test
    void disabledRealmIsInactive() {
        when(realm.isEnabled()).thenReturn(false);

        assertInactive(introspect(claims(now())));
    }

    @Test
    void tokenIssuedBeforeClientNotBeforeIsInactive() {
        long iat = now() - 60;
        when(client.getNotBefore()).thenReturn((int) (iat + 1));

        assertInactive(introspect(claims(iat)));
    }

    @Test
    void tokenIssuedBeforeRealmNotBeforeIsInactive() {
        long iat = now() - 60;
        when(realm.getNotBefore()).thenReturn((int) (iat + 1));

        assertInactive(introspect(claims(iat)));
    }

    @Test
    void tokenIssuedAtNotBeforeIsActive() {
        long iat = now() - 60;
        when(client.getNotBefore()).thenReturn((int) iat);

        assertEquals(true, introspect(claims(iat)).get("active"));
    }

    @Test
    void tokenWithoutIatIsInactiveWhenNotBeforeIsSet() {
        when(client.getNotBefore()).thenReturn((int) (now() - 60));
        Map<String, Object> claims = claims(now());
        claims.remove("iat");

        assertInactive(introspect(claims));
    }

    @Test
    void clientWithoutRsinMapperIsInactive() {
        withMappers();

        assertInactive(introspect(claims(now())));
    }

    @Test
    void clientWithoutRsinMapperCannotChooseTenant() {
        withMappers(hardcodedClaimMapper("other_claim", "x"));
        Map<String, Object> claims = claims(now());
        claims.put("rsin", OTHER_RSIN);

        assertInactive(introspect(claims));
    }

    @Test
    void clientWithEmptyRsinMapperValueIsInactive() {
        withMappers(hardcodedClaimMapper("rsin", ""));

        assertInactive(introspect(claims(now())));
    }

    @Test
    void tokenRsinIsOverriddenByMapper() {
        Map<String, Object> claims = claims(now());
        claims.put("rsin", OTHER_RSIN);

        Map<String, Object> result = introspect(claims);

        assertEquals(true, result.get("active"));
        assertEquals(MAPPED_RSIN, result.get("rsin"));
    }

    private void withMappers(ProtocolMapperModel... mappers) {
        when(client.getProtocolMappersStream()).thenAnswer(inv -> Stream.of(mappers));
    }

    private static ProtocolMapperModel hardcodedClaimMapper(String claimName, String claimValue) {
        ProtocolMapperModel mapper = new ProtocolMapperModel();
        mapper.setProtocolMapper("oidc-hardcoded-claim-mapper");
        Map<String, String> config = new HashMap<>();
        config.put("claim.name", claimName);
        config.put("claim.value", claimValue);
        mapper.setConfig(config);
        return mapper;
    }

    private static long now() {
        return System.currentTimeMillis() / 1000;
    }

    private static Map<String, Object> claims(long iat) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("client_id", CLIENT_ID);
        claims.put("iat", iat);
        claims.put("exp", now() + 300);
        return claims;
    }

    private Map<String, Object> introspect(Map<String, Object> claims) {
        return provider.validateCustomJwt(sign(claims));
    }

    private static void assertInactive(Map<String, Object> result) {
        assertEquals(Map.of("active", false), result);
    }

    private static String sign(Map<String, Object> claims) {
        try {
            Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
            String header = b64.encodeToString("{\"alg\":\"HS256\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));
            String payload = b64.encodeToString(JsonSerialization.writeValueAsBytes(claims));
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(SECRET.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            String signature = b64.encodeToString(mac.doFinal((header + "." + payload).getBytes(StandardCharsets.UTF_8)));
            return header + "." + payload + "." + signature;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
