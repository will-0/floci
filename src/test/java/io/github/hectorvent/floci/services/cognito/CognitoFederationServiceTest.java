package io.github.hectorvent.floci.services.cognito;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.core.storage.InMemoryStorage;
import io.github.hectorvent.floci.services.acm.AcmService;
import io.github.hectorvent.floci.services.cognito.model.CognitoAuthorizationCode;
import io.github.hectorvent.floci.services.cognito.model.CognitoAuthorizationTransaction;
import io.github.hectorvent.floci.services.cognito.model.CognitoGroup;
import io.github.hectorvent.floci.services.cognito.model.CognitoUser;
import io.github.hectorvent.floci.services.cognito.model.IdentityProvider;
import io.github.hectorvent.floci.services.cognito.model.ResourceServer;
import io.github.hectorvent.floci.services.cognito.model.RevokedTokenInfo;
import io.github.hectorvent.floci.services.cognito.model.UserPool;
import io.github.hectorvent.floci.services.cognito.model.UserPoolClient;
import io.github.hectorvent.floci.services.cognito.model.UserPoolDomain;
import io.github.hectorvent.floci.services.lambda.LambdaService;
import io.github.hectorvent.floci.services.lambda.model.InvokeResult;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class CognitoFederationServiceTest {

    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-09-16T00:00:00Z"), ZoneOffset.UTC);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private LambdaService lambdaService;
    private KeyPair signingKey;
    private String jwksOverride;
    private HttpServer oidcServer;
    private CognitoService cognitoService;
    private CognitoFederationStateStore stateStore;
    private CognitoFederationService federationService;
    private UserPool pool;
    private final AtomicReference<Request> tokenRequest = new AtomicReference<>();
    private final AtomicReference<Request> claimsRequest = new AtomicReference<>();
    private volatile int tokenStatus;
    private volatile String tokenResponse;
    private volatile int claimsStatus;
    private volatile String claimsResponse;

    @BeforeEach
    void setUp() throws IOException {
        jwksOverride = null;
        oidcServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        oidcServer.createContext("/token", this::handleToken);
        oidcServer.createContext("/userinfo", this::handleClaims);
        oidcServer.start();

        lambdaService = mock(LambdaService.class);
        cognitoService = new CognitoService(
                new InMemoryStorage<String, UserPool>(),
                new InMemoryStorage<String, UserPoolClient>(),
                new InMemoryStorage<String, ResourceServer>(),
                new InMemoryStorage<String, UserPoolDomain>(),
                new InMemoryStorage<String, IdentityProvider>(),
                new InMemoryStorage<String, CognitoUser>(),
                new InMemoryStorage<String, CognitoGroup>(),
                new InMemoryStorage<String, RevokedTokenInfo>(),
                "http://localhost:4566",
                new RegionResolver("us-east-1", "000000000000"),
                lambdaService,
                mock(AcmService.class),
                null,
                null,
                null);
        stateStore = new CognitoFederationStateStore(CLOCK);
        federationService = new CognitoFederationService(
                cognitoService, stateStore, new CognitoOidcClient(MAPPER), CLOCK);
        pool = cognitoService.createUserPool(Map.of("PoolName", "FederationPool"), "us-east-1");
        tokenStatus = 200;
        tokenResponse = "{\"access_token\":\"provider-access-token\"}";
        claimsStatus = 200;
        claimsResponse = "{\"sub\":\"provider-subject\",\"iss\":\"https://issuer.example.test\","
                + "\"email\":\"alice@example.test\",\"name\":\"Alice Provider\"}";
    }

    @AfterEach
    void tearDown() {
        oidcServer.stop(0);
    }

    private String inboundState() throws Exception {
        signingKey = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        RSAPublicKey key = (RSAPublicKey) signingKey.getPublic();
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        oidcServer.createContext("/jwks", exchange -> {
            byte[] body = jwksOverride != null ? jwksOverride.getBytes(StandardCharsets.UTF_8) : MAPPER.writeValueAsBytes(Map.of("keys", List.of(Map.of("kty", "RSA", "kid", "proof",
                    "alg", "RS256", "n", encoder.encodeToString(key.getModulus().toByteArray()),
                    "e", encoder.encodeToString(key.getPublicExponent().toByteArray())))));
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        pool.setLambdaConfig(Map.of("InboundFederation", Map.of("LambdaArn", "arn:aws:lambda:::inbound", "LambdaVersion", "V1_0")));
        createProvider(Map.of("client_id", "provider-client", "oidc_issuer", "https://issuer.example.test",
                "authorize_url", "https://issuer.example.test/authorize", "token_url", endpoint("/token"),
                "attributes_url", endpoint("/userinfo"), "jwks_uri", endpoint("/jwks")), Map.of("email", "email", "name", "name"));
        UserPoolClient client = cognitoService.createUserPoolClient(pool.getId(), "inbound-client", false,
                true, List.of("code"), List.of("openid"), null, List.of("https://application.example.test/callback"),
                null, List.of(), null, null, List.of(), null, List.of(), null, List.of("ExampleOidc"), null, List.of(), null, null);
        String redirect = federationService.beginAuthorization(pool.getId(), client.getClientId(),
                "https://application.example.test/callback", List.of("openid"), "nonce-value", "ExampleOidc");
        return queryValue(redirect, "state");
    }

    private void signedToken(Map<String, Object> overrides) throws Exception {
        Map<String, Object> claims = new LinkedHashMap<>(Map.of("iss", "https://issuer.example.test",
                "sub", "provider-subject", "aud", "provider-client", "exp", Instant.now().plusSeconds(600).getEpochSecond(),
                "iat", Instant.now().getEpochSecond(), "nonce", "nonce-value"));
        claims.putAll(overrides);
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        String content = encoder.encodeToString(MAPPER.writeValueAsBytes(Map.of("alg", "RS256", "kid", "proof")))
                + "." + encoder.encodeToString(MAPPER.writeValueAsBytes(claims));
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(signingKey.getPrivate());
        signer.update(content.getBytes(StandardCharsets.US_ASCII));
        tokenResponse = MAPPER.writeValueAsString(Map.of("access_token", "provider-access-token", "id_token",
                content + "." + encoder.encodeToString(signer.sign()), "expires_in", 3600));
    }

    @Test
    void inboundFederationReceivesVerifiedRawProviderDataBeforeUserCreationAndMapsItsResponse() throws Exception {
        String state = inboundState();
        signedToken(Map.of());
        AtomicReference<JsonNode> event = new AtomicReference<>();
        when(lambdaService.invoke(anyString(), eq("arn:aws:lambda:::inbound"), any(byte[].class), any()))
                .thenAnswer(call -> {
                    assertTrue(cognitoService.listUsers(pool.getId(), null).isEmpty());
                    event.set(MAPPER.readTree((byte[]) call.getArgument(2)));
                    return new InvokeResult(200, null, MAPPER.writeValueAsBytes(Map.of("response", Map.of(
                            "userAttributesToMap", Map.of("email", "transformed@example.test")))), null, "proof");
                });
        String code = federationService.completeAuthorization(state, "provider-code");
        CognitoAuthorizationCode authorization = stateStore.consumeAuthorizationCode(code).orElseThrow();
        CognitoUser user = cognitoService.adminGetUser(pool.getId(), authorization.userId());
        assertEquals("transformed@example.test", user.getAttributes().get("email"));
        assertFalse(user.getAttributes().containsKey("name"));
        assertEquals("1", event.get().path("version").asText());
        assertEquals("InboundFederation_ExternalProvider", event.get().path("triggerSource").asText());
        assertEquals("ExampleOidc", event.get().path("request").path("providerName").asText());
        assertEquals("OIDC", event.get().path("request").path("providerType").asText());
        JsonNode attributes = event.get().path("request").path("attributes");
        assertEquals("provider-subject", attributes.path("idToken").path("sub").asText());
        assertEquals("alice@example.test", attributes.path("userInfo").path("email").asText());
        assertEquals(3600, attributes.path("tokenResponse").path("expires_in").asInt());
        assertTrue(attributes.path("tokenResponse").path("id_token").isTextual());
        assertEquals(authorization.clientId(), event.get().path("callerContext").path("clientId").asText());
    }

    @ParameterizedTest
    @ValueSource(strings = {"nonce", "audience", "expired", "signature", "subject", "jwks", "missing", "blank"})
    void inboundFederationRejectsUnverifiedIdentityBeforeInvokingLambdaOrCreatingUser(String failure) throws Exception {
        String state = inboundState();
        signedToken(switch (failure) {
            case "nonce" -> Map.of("nonce", "foreign-nonce");
            case "audience" -> Map.of("aud", "foreign-client");
            case "expired" -> Map.of("exp", Instant.now().minusSeconds(600).getEpochSecond());
            case "subject" -> Map.of("sub", "foreign-subject");
            default -> Map.of();
        });
        if ("missing".equals(failure) || "blank".equals(failure)) {
            tokenResponse = MAPPER.writeValueAsString("missing".equals(failure)
                    ? Map.of("access_token", "provider-access-token")
                    : Map.of("access_token", "provider-access-token", "id_token", " "));
        }
        if ("jwks".equals(failure)) {
            jwksOverride = "null";
        }
        if ("signature".equals(failure)) {
            String token = MAPPER.readTree(tokenResponse).path("id_token").asText();
            String[] pieces = token.split("\\.");
            pieces[2] = Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[256]);
            tokenResponse = MAPPER.writeValueAsString(Map.of("access_token", "provider-access-token", "id_token", String.join(".", pieces)));
        }
        AwsException error = assertThrows(AwsException.class, () -> federationService.completeAuthorization(state, "provider-code"));
        assertEquals("NotAuthorizedException", error.getErrorCode());
        assertTrue(cognitoService.listUsers(pool.getId(), null).isEmpty());
        verifyNoInteractions(lambdaService);
    }

    @ParameterizedTest
    @ValueSource(strings = {"failed", "malformed", "empty"})
    void inboundFederationPropagatesFailuresAndEmptyAttributeMapIsNoOp(String behavior) throws Exception {
        String state = inboundState();
        signedToken(Map.of());
        InvokeResult response = "failed".equals(behavior)
                ? new InvokeResult(200, "Unhandled", MAPPER.writeValueAsBytes(Map.of("errorMessage", "synthetic refusal")), null, "proof")
                : new InvokeResult(200, null, MAPPER.writeValueAsBytes(Map.of("response", "empty".equals(behavior)
                        ? Map.of("userAttributesToMap", Map.of()) : Map.of())), null, "proof");
        when(lambdaService.invoke(anyString(), eq("arn:aws:lambda:::inbound"), any(byte[].class), any())).thenReturn(response);
        if ("empty".equals(behavior)) {
            String code = federationService.completeAuthorization(state, "provider-code");
            CognitoAuthorizationCode authorization = stateStore.consumeAuthorizationCode(code).orElseThrow();
            assertEquals("alice@example.test", cognitoService.adminGetUser(pool.getId(), authorization.userId()).getAttributes().get("email"));
        } else {
            AwsException error = assertThrows(AwsException.class, () -> federationService.completeAuthorization(state, "provider-code"));
            assertEquals("failed".equals(behavior) ? "UserLambdaValidationException" : "InvalidLambdaResponseException", error.getErrorCode());
            assertTrue(cognitoService.listUsers(pool.getId(), null).isEmpty());
        }
    }

    @Test
    void beginAuthorizationRejectsProviderWithoutAuthorizeEndpoint() {
        createProvider(Map.of(
                "client_id", "provider-client",
                "token_url", endpoint("/token"),
                "attributes_url", endpoint("/userinfo")), Map.of());

        AwsException exception = assertThrows(AwsException.class, () -> federationService.beginAuthorization(
                pool.getId(), "cognito-client", "https://application.example.test/callback",
                List.of("openid"), "nonce-value", "ExampleOidc"));

        assertEquals("InvalidParameterException", exception.getErrorCode());
    }

    @Test
    void beginAuthorizationRejectsNonOidcProviderBeforeStoringState() {
        createProvider("ExampleGoogle", "Google", Map.of(
                "client_id", "provider-client",
                "authorize_url", "https://provider.example.test/authorize",
                "token_url", endpoint("/token"),
                "attributes_url", endpoint("/userinfo")), Map.of());

        AwsException exception = assertThrows(AwsException.class, () -> federationService.beginAuthorization(
                pool.getId(), "cognito-client", "https://application.example.test/callback",
                List.of("openid"), "nonce-value", "ExampleGoogle"));

        assertEquals("InvalidParameterException", exception.getErrorCode());
        assertNull(tokenRequest.get());
        assertNull(claimsRequest.get());
    }

    @Test
    void beginAuthorizationStoresRelyingPartyStateInTransaction() {
        createDefaultProvider();

        String redirect = federationService.beginAuthorization(
                pool.getId(), "cognito-client", "https://application.example.test/callback",
                List.of("openid"), List.of("openid"), "nonce-value", "ExampleOidc", "relying-party-state", null);

        CognitoAuthorizationTransaction transaction = stateStore.consumeTransaction(queryValue(redirect, "state")).orElseThrow();
        assertEquals("relying-party-state", transaction.relyingPartyState());
    }

    @Test
    void completeAuthorizationCarriesTheNonceAndCodeChallengeIntoTheCode() {
        createDefaultProvider();
        String challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        String redirect = federationService.beginAuthorization(
                pool.getId(), "cognito-client", "https://application.example.test/callback",
                List.of("openid"), List.of("openid"), "nonce-value", "ExampleOidc", null, challenge);

        String authorizationCode = federationService.completeAuthorization(queryValue(redirect, "state"), "provider-code");

        CognitoAuthorizationCode storedCode = stateStore.consumeAuthorizationCode(authorizationCode).orElseThrow();
        assertEquals("nonce-value", storedCode.nonce());
        assertEquals(challenge, storedCode.codeChallenge());
        assertFalse(redirect.contains(challenge), "the challenge stays with Cognito: " + redirect);
    }

    @Test
    void completeAuthorizationRejectsNonOidcProvider() {
        createProvider("ExampleGoogle", "Google", Map.of(
                "client_id", "provider-client",
                "authorize_url", "https://provider.example.test/authorize",
                "token_url", endpoint("/token"),
                "attributes_url", endpoint("/userinfo")), Map.of());
        String state = putTransaction("ExampleGoogle");

        AwsException exception = assertThrows(AwsException.class,
                () -> federationService.completeAuthorization(state, "provider-code"));

        assertEquals("InvalidParameterException", exception.getErrorCode());
        assertNull(tokenRequest.get());
        assertNull(claimsRequest.get());
    }

    @Test
    void completeAuthorizationRejectsProviderWithoutTokenEndpoint() {
        createProvider(Map.of(
                "client_id", "provider-client",
                "authorize_url", "https://provider.example.test/authorize",
                "attributes_url", endpoint("/userinfo")), Map.of());
        String state = beginAuthorization();

        AwsException exception = assertThrows(AwsException.class,
                () -> federationService.completeAuthorization(state, "provider-code"));

        assertEquals("InvalidParameterException", exception.getErrorCode());
    }

    @Test
    void completeAuthorizationRejectsProviderWithoutClaimsEndpoint() {
        createProvider(Map.of(
                "client_id", "provider-client",
                "authorize_url", "https://provider.example.test/authorize",
                "token_url", endpoint("/token")), Map.of());
        String state = beginAuthorization();

        AwsException exception = assertThrows(AwsException.class,
                () -> federationService.completeAuthorization(state, "provider-code"));

        assertEquals("InvalidParameterException", exception.getErrorCode());
    }

    @Test
    void completeAuthorizationConvertsInvalidTokenEndpointUriToAwsException() {
        createProvider(Map.of(
                "client_id", "provider-client",
                "authorize_url", "https://provider.example.test/authorize",
                "token_url", "http://[invalid",
                "attributes_url", endpoint("/userinfo")), Map.of());
        String state = beginAuthorization();

        AwsException exception = assertThrows(AwsException.class,
                () -> federationService.completeAuthorization(state, "provider-code"));

        assertEquals("InvalidParameterException", exception.getErrorCode());
    }

    @Test
    void completeAuthorizationRejectsUnsupportedTokenEndpointScheme() {
        createProvider(Map.of(
                "client_id", "provider-client",
                "authorize_url", "https://provider.example.test/authorize",
                "token_url", "ftp://provider.example.test/token",
                "attributes_url", endpoint("/userinfo")), Map.of());
        String state = beginAuthorization();

        AwsException exception = assertThrows(AwsException.class,
                () -> federationService.completeAuthorization(state, "provider-code"));

        assertEquals("InvalidParameterException", exception.getErrorCode());
    }

    @Test
    void completeAuthorizationRejectsUnsupportedClaimsEndpointScheme() {
        createProvider(Map.of(
                "client_id", "provider-client",
                "authorize_url", "https://provider.example.test/authorize",
                "token_url", endpoint("/token"),
                "attributes_url", "ftp://provider.example.test/userinfo"), Map.of());
        String state = beginAuthorization();

        AwsException exception = assertThrows(AwsException.class,
                () -> federationService.completeAuthorization(state, "provider-code"));

        assertEquals("InvalidParameterException", exception.getErrorCode());
    }

    @Test
    void completeAuthorizationRejectsFailedTokenExchange() {
        createDefaultProvider();
        tokenStatus = 400;
        tokenResponse = "{\"error\":\"invalid_grant\"}";
        String state = beginAuthorization();

        AwsException exception = assertThrows(AwsException.class,
                () -> federationService.completeAuthorization(state, "provider-code"));

        assertEquals("NotAuthorizedException", exception.getErrorCode());
    }

    @Test
    void completeAuthorizationRejectsFailedClaimsRequest() {
        createDefaultProvider();
        claimsStatus = 503;
        claimsResponse = "{\"error\":\"temporarily_unavailable\"}";
        String state = beginAuthorization();

        AwsException exception = assertThrows(AwsException.class,
                () -> federationService.completeAuthorization(state, "provider-code"));

        assertEquals("NotAuthorizedException", exception.getErrorCode());
    }

    @Test
    void completeAuthorizationRejectsClaimsWithoutSubject() {
        createDefaultProvider();
        claimsResponse = "{\"email\":\"alice@example.test\"}";
        String state = beginAuthorization();

        AwsException exception = assertThrows(AwsException.class,
                () -> federationService.completeAuthorization(state, "provider-code"));

        assertEquals("InvalidParameterException", exception.getErrorCode());
    }

    @Test
    void completeAuthorizationMapsClaimsAndUsesOidcRequests() {
        createDefaultProvider();
        String state = beginAuthorization();

        String authorizationCode = federationService.completeAuthorization(state, "provider code");

        CognitoAuthorizationCode storedCode = stateStore.consumeAuthorizationCode(authorizationCode).orElseThrow();
        CognitoUser user = cognitoService.adminGetUser(pool.getId(), storedCode.userId());
        assertEquals("alice@example.test", user.getAttributes().get("email"));
        assertEquals("Alice Provider", user.getAttributes().get("name"));
        assertEquals("ExampleOidc", user.getFederatedProviderName());
        assertEquals("provider-subject", user.getFederatedSubject());

        Request observedTokenRequest = tokenRequest.get();
        assertNotNull(observedTokenRequest);
        assertEquals("POST", observedTokenRequest.method());
        assertEquals("authorization_code", formValue(observedTokenRequest.body(), "grant_type"));
        assertEquals("provider-client", formValue(observedTokenRequest.body(), "client_id"));
        assertEquals("provider-secret", formValue(observedTokenRequest.body(), "client_secret"));
        assertEquals("provider code", formValue(observedTokenRequest.body(), "code"));
        assertEquals(cognitoService.getIdentityProviderCallbackEndpoint(pool.getId()),
                formValue(observedTokenRequest.body(), "redirect_uri"));

        Request observedClaimsRequest = claimsRequest.get();
        assertNotNull(observedClaimsRequest);
        assertEquals("GET", observedClaimsRequest.method());
        assertEquals("Bearer provider-access-token", observedClaimsRequest.authorization());
    }

    @Test
    void completeAuthorizationProvisionsNewFederatedUser() {
        createDefaultProvider();

        CognitoAuthorizationCode storedCode = completeAndConsumeAuthorizationCode();
        CognitoUser user = cognitoService.adminGetUser(pool.getId(), storedCode.userId());

        assertEquals(pool.getId(), user.getUserPoolId());
        assertEquals("CONFIRMED", user.getUserStatus());
        assertTrue(user.isEnabled());
        assertFalse(user.getUsername().isBlank());
        assertNotNull(user.getAttributes().get("sub"));
    }

    @Test
    void completeAuthorizationReconcilesExistingFederatedUserWithoutLosingOtherAttributes() {
        createDefaultProvider();
        CognitoAuthorizationCode firstCode = completeAndConsumeAuthorizationCode();
        CognitoUser firstUser = cognitoService.adminGetUser(pool.getId(), firstCode.userId());
        cognitoService.adminUpdateUserAttributes(pool.getId(), firstUser.getUsername(),
                Map.of("custom:note", "preserve-me", "email", "old@example.test"));
        claimsResponse = "{\"sub\":\"provider-subject\",\"iss\":\"https://issuer.example.test\","
                + "\"email\":\"new@example.test\",\"name\":\"Updated Provider\"}";

        CognitoAuthorizationCode secondCode = completeAndConsumeAuthorizationCode();
        CognitoUser reconciledUser = cognitoService.adminGetUser(pool.getId(), secondCode.userId());

        assertEquals(firstUser.getUsername(), reconciledUser.getUsername());
        assertEquals("new@example.test", reconciledUser.getAttributes().get("email"));
        assertEquals("Updated Provider", reconciledUser.getAttributes().get("name"));
        assertEquals("preserve-me", reconciledUser.getAttributes().get("custom:note"));
    }

    @Test
    void completeAuthorizationStoresAwsCompatibleIdentityFields() throws Exception {
        createDefaultProvider();

        CognitoAuthorizationCode storedCode = completeAndConsumeAuthorizationCode();
        CognitoUser user = cognitoService.adminGetUser(pool.getId(), storedCode.userId());
        JsonNode identity = MAPPER.readTree(user.getAttributes().get("identities")).get(0);
        List<String> fieldNames = new ArrayList<>();
        identity.fieldNames().forEachRemaining(fieldNames::add);

        assertEquals(List.of("userId", "providerName", "providerType", "issuer", "primary", "dateCreated"),
                fieldNames);
        assertEquals("provider-subject", identity.path("userId").asText());
        assertEquals("ExampleOidc", identity.path("providerName").asText());
        assertEquals("OIDC", identity.path("providerType").asText());
        assertEquals("https://issuer.example.test", identity.path("issuer").asText());
        assertFalse(identity.path("primary").asBoolean());
        assertTrue(identity.path("dateCreated").asLong() > 0L);
    }

    private IdentityProvider createDefaultProvider() {
        return createProvider(Map.of(
                "client_id", "provider-client",
                "client_secret", "provider-secret",
                "authorize_url", "https://provider.example.test/authorize",
                "token_url", endpoint("/token"),
                "attributes_url", endpoint("/userinfo")),
                Map.of("email", "email", "name", "name"));
    }

    private IdentityProvider createProvider(Map<String, String> details, Map<String, String> attributeMapping) {
        return createProvider("ExampleOidc", "OIDC", details, attributeMapping);
    }

    private IdentityProvider createProvider(String providerName, String providerType, Map<String, String> details,
                                            Map<String, String> attributeMapping) {
        return cognitoService.createIdentityProvider(pool.getId(), providerName, providerType, details,
                attributeMapping, List.of());
    }

    private CognitoAuthorizationCode completeAndConsumeAuthorizationCode() {
        String authorizationCode = federationService.completeAuthorization(beginAuthorization(), "provider-code");
        return stateStore.consumeAuthorizationCode(authorizationCode).orElseThrow();
    }

    private String beginAuthorization() {
        String redirect = federationService.beginAuthorization(
                pool.getId(), "cognito-client", "https://application.example.test/callback",
                List.of("openid"), "nonce-value", "ExampleOidc");
        return queryValue(redirect, "state");
    }

    private String putTransaction(String providerName) {
        return stateStore.putTransaction(new CognitoAuthorizationTransaction(
                pool.getId(), "cognito-client", "https://application.example.test/callback",
                List.of("openid"), "nonce-value", providerName, null, null, CLOCK.instant().plusSeconds(60)));
    }

    private String endpoint(String path) {
        return "http://127.0.0.1:" + oidcServer.getAddress().getPort() + path;
    }

    private void handleToken(HttpExchange exchange) throws IOException {
        tokenRequest.set(new Request(exchange.getRequestMethod(),
                new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8),
                exchange.getRequestHeaders().getFirst("Authorization")));
        writeResponse(exchange, tokenStatus, tokenResponse);
    }

    private void handleClaims(HttpExchange exchange) throws IOException {
        claimsRequest.set(new Request(exchange.getRequestMethod(),
                new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8),
                exchange.getRequestHeaders().getFirst("Authorization")));
        writeResponse(exchange, claimsStatus, claimsResponse);
    }

    private void writeResponse(HttpExchange exchange, int status, String response) throws IOException {
        byte[] body = response.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, body.length);
        exchange.getResponseBody().write(body);
        exchange.close();
    }

    private String queryValue(String uri, String name) {
        String query = URI.create(uri).getRawQuery();
        for (String pair : query.split("&")) {
            String[] parts = pair.split("=", 2);
            if (parts.length == 2 && name.equals(URLDecoder.decode(parts[0], StandardCharsets.UTF_8))) {
                return URLDecoder.decode(parts[1], StandardCharsets.UTF_8);
            }
        }
        throw new AssertionError("Query parameter " + name + " was absent from " + uri);
    }

    private String formValue(String form, String name) {
        return queryValue("https://form.example.test/?" + form, name);
    }

    private record Request(String method, String body, String authorization) {
    }
}
