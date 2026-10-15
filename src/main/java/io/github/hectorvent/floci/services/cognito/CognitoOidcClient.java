package io.github.hectorvent.floci.services.cognito;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.common.PublicKeys;
import io.github.hectorvent.floci.core.common.WebIdentityTokenVerifier;
import io.github.hectorvent.floci.services.cognito.model.IdentityProvider;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Function;

@ApplicationScoped
public class CognitoOidcClient {

    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(10);
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(15);

    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;

    @Inject
    public CognitoOidcClient(ObjectMapper objectMapper) {
        this(HttpClient.newBuilder().connectTimeout(CONNECT_TIMEOUT).build(), objectMapper);
    }

    CognitoOidcClient(HttpClient httpClient, ObjectMapper objectMapper) {
        this.httpClient = httpClient;
        this.objectMapper = objectMapper;
    }

    public Map<String, String> discoverProviderDetails(Map<String, String> supplied) {
        Map<String, String> details = new LinkedHashMap<>(supplied);
        String issuer = details.get("oidc_issuer");
        Map<String, String> endpoints = Map.of("authorize_url", "authorization_endpoint",
                "token_url", "token_endpoint", "attributes_url", "userinfo_endpoint", "jwks_uri", "jwks_uri");
        if (issuer == null || issuer.isBlank() || endpoints.keySet().stream()
                .allMatch(key -> details.containsKey(key) && !details.get(key).isBlank())) {
            return details;
        }
        try {
            URI uri = URI.create(issuer);
            if (uri.getHost() == null || !("http".equals(uri.getScheme()) || "https".equals(uri.getScheme()))
                    || uri.getRawUserInfo() != null || uri.getRawQuery() != null || uri.getRawFragment() != null) {
                throw new IllegalArgumentException("Invalid OIDC issuer");
            }
            String discovery = issuer.replaceFirst("/$", "") + "/.well-known/openid-configuration";
            HttpRequest request = HttpRequest.newBuilder(URI.create(discovery)).timeout(REQUEST_TIMEOUT)
                    .header("Accept", "application/json").GET().build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw new IllegalArgumentException("OIDC discovery returned an unsuccessful status");
            }
            JsonNode metadata = objectMapper.readTree(response.body());
            if (metadata == null || !metadata.isObject() || !issuer.equals(metadata.path("issuer").asText())) {
                throw new IllegalArgumentException("OIDC discovery issuer does not match");
            }
            for (Map.Entry<String, String> entry : endpoints.entrySet()) {
                if (!details.containsKey(entry.getKey()) || details.get(entry.getKey()).isBlank()) {
                    String endpoint = metadata.path(entry.getValue()).asText();
                    URI endpointUri = URI.create(endpoint);
                    if (endpointUri.getHost() == null || !("http".equals(endpointUri.getScheme())
                            || "https".equals(endpointUri.getScheme())) || endpointUri.getRawUserInfo() != null
                            || endpointUri.getRawFragment() != null) {
                        throw new IllegalArgumentException("OIDC discovery endpoint is invalid");
                    }
                    details.put(entry.getKey(), endpoint);
                }
            }
            return details;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new AwsException("InvalidParameterException", "OIDC discovery was interrupted", 400);
        } catch (IOException | IllegalArgumentException e) {
            throw new AwsException("InvalidParameterException", "OIDC discovery metadata could not be verified", 400);
        }
    }

    public JsonNode verifyIdToken(IdentityProvider provider, JsonNode response, String nonce) {
        String token = response.path("id_token").asText(null);
        if (token == null || token.isBlank()) {
            throw new AwsException("NotAuthorizedException", "Identity provider did not return an ID token", 400);
        }
        try {
            String[] parts = token.split("\\.", -1);
            if (parts.length != 3) {
                throw new IllegalArgumentException("Malformed ID token");
            }
            JsonNode header = objectMapper.readTree(Base64.getUrlDecoder().decode(parts[0]));
            if (header == null || !header.isObject()) {
                throw new IllegalArgumentException("Malformed ID token header");
            }
            String kid = header.path("kid").asText(null);
            HttpRequest request = buildRequest(requiredEndpoint(provider, "jwks_uri", "JWKS"),
                    provider.getProviderName(), "JWKS", builder -> builder.header("Accept", "application/json").GET().build());
            JsonNode jwks = send(request, "JWKS retrieval");
            if (jwks == null || !jwks.path("keys").isArray()) {
                throw new IllegalArgumentException("Invalid provider JWKS");
            }
            for (JsonNode key : jwks.path("keys")) {
                if (!"RSA".equals(key.path("kty").asText()) || (kid != null && !kid.equals(key.path("kid").asText()))
                        || (key.has("alg") && !"RS256".equals(key.path("alg").asText()))
                        || (key.has("use") && !"sig".equals(key.path("use").asText()))) {
                    continue;
                }
                RSAPublicKey publicKey = PublicKeys.rsa(new BigInteger(1, Base64.getUrlDecoder().decode(key.path("n").asText())),
                        new BigInteger(1, Base64.getUrlDecoder().decode(key.path("e").asText())));
                new WebIdentityTokenVerifier(objectMapper).verify(token, publicKey,
                        requiredProviderDetail(provider, "oidc_issuer"), requiredProviderDetail(provider, "client_id"));
                JsonNode claims = objectMapper.readTree(Base64.getUrlDecoder().decode(parts[1]));
                if (nonce != null && !nonce.equals(claims.path("nonce").asText(null))) {
                    throw new IllegalArgumentException("ID token nonce does not match");
                }
                return claims;
            }
            throw new IllegalArgumentException("ID token signing key not found");
        } catch (IOException | GeneralSecurityException | WebIdentityTokenVerifier.InvalidTokenException
                 | IllegalArgumentException e) {
            throw new AwsException("NotAuthorizedException", "Identity provider ID token could not be verified", 400);
        }
    }

    public JsonNode exchangeCode(IdentityProvider provider, String code, String redirectUri) {
        String tokenEndpoint = requiredEndpoint(provider, "token_url", "token");
        Map<String, String> form = new LinkedHashMap<>();
        form.put("grant_type", "authorization_code");
        form.put("client_id", requiredProviderDetail(provider, "client_id"));
        String clientSecret = provider.getProviderDetails().get("client_secret");
        if (clientSecret != null && !clientSecret.isBlank()) {
            form.put("client_secret", clientSecret);
        }
        form.put("code", code);
        form.put("redirect_uri", redirectUri);

        HttpRequest request = buildRequest(tokenEndpoint, provider.getProviderName(), "token", builder -> builder
                .header("Accept", "application/json")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(formEncode(form)))
                .build());
        return send(request, "token exchange");
    }

    public JsonNode fetchClaims(IdentityProvider provider, String accessToken) {
        String claimsEndpoint = requiredEndpoint(provider, "attributes_url", "claims");
        if (accessToken == null || accessToken.isBlank()) {
            throw new AwsException("NotAuthorizedException", "Identity provider did not return an access token", 400);
        }

        HttpRequest request = buildRequest(claimsEndpoint, provider.getProviderName(), "claims", builder -> builder
                .header("Accept", "application/json")
                .header("Authorization", "Bearer " + accessToken)
                .GET()
                .build());
        return send(request, "claims request");
    }

    private JsonNode send(HttpRequest request, String operation) {
        try {
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() < 200 || response.statusCode() >= 300) {
                throw new AwsException("NotAuthorizedException", "Identity provider " + operation + " failed", 400);
            }
            JsonNode responseJson = objectMapper.readTree(response.body());
            if (responseJson == null || !responseJson.isObject()) {
                throw new AwsException("NotAuthorizedException", "Identity provider " + operation
                        + " returned an invalid response", 400);
            }
            return responseJson;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new AwsException("NotAuthorizedException", "Identity provider " + operation + " was interrupted", 400);
        } catch (IOException | IllegalArgumentException e) {
            throw new AwsException("NotAuthorizedException", "Identity provider " + operation + " failed", 400);
        }
    }

    private String requiredEndpoint(IdentityProvider provider, String detailName, String endpointName) {
        String endpoint = provider.getProviderDetails().get(detailName);
        if (endpoint == null || endpoint.isBlank()) {
            throw new AwsException("InvalidParameterException", "Identity provider " + provider.getProviderName()
                    + " does not have a " + endpointName + " endpoint configured", 400);
        }
        return endpoint;
    }

    private HttpRequest buildRequest(String endpoint, String providerName, String endpointName,
                                     Function<HttpRequest.Builder, HttpRequest> requestFactory) {
        try {
            URI uri = URI.create(endpoint);
            if (!"http".equalsIgnoreCase(uri.getScheme()) && !"https".equalsIgnoreCase(uri.getScheme())) {
                throw new IllegalArgumentException("Unsupported URI scheme");
            }
            HttpRequest.Builder builder = HttpRequest.newBuilder(uri).timeout(REQUEST_TIMEOUT);
            return requestFactory.apply(builder);
        } catch (IllegalArgumentException e) {
            throw new AwsException("InvalidParameterException", "Identity provider " + providerName
                    + " has an invalid " + endpointName + " endpoint", 400);
        }
    }

    private String requiredProviderDetail(IdentityProvider provider, String detailName) {
        String value = provider.getProviderDetails().get(detailName);
        if (value == null || value.isBlank()) {
            throw new AwsException("InvalidParameterException", "Identity provider " + provider.getProviderName()
                    + " does not have " + detailName + " configured", 400);
        }
        return value;
    }

    private String formEncode(Map<String, String> form) {
        StringBuilder encoded = new StringBuilder();
        for (Map.Entry<String, String> entry : form.entrySet()) {
            if (!encoded.isEmpty()) {
                encoded.append('&');
            }
            encoded.append(URLEncoder.encode(entry.getKey(), StandardCharsets.UTF_8));
            encoded.append('=');
            encoded.append(URLEncoder.encode(entry.getValue(), StandardCharsets.UTF_8));
        }
        return encoded.toString();
    }
}
