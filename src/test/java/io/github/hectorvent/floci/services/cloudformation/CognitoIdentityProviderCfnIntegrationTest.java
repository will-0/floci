package io.github.hectorvent.floci.services.cloudformation;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.sun.net.httpserver.HttpServer;
import io.github.hectorvent.floci.core.common.XmlParser;
import io.github.hectorvent.floci.testing.RestAssuredJsonUtils;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.specification.RequestSpecification;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import static io.github.hectorvent.floci.services.cognito.CognitoRestAssuredUtils.cognitoAction;
import static io.github.hectorvent.floci.services.cognito.CognitoRestAssuredUtils.cognitoJson;
import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@QuarkusTest
class CognitoIdentityProviderCfnIntegrationTest {
    private static final String AUTH = "AWS4-HMAC-SHA256 Credential=test/20261015/us-east-1/cloudformation/aws4_request";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    @BeforeAll
    static void configure() {
        RestAssuredJsonUtils.configureAwsContentTypes();
    }

    @Test
    void realStackCreatesUpdatesReplacesAndDeletesProviderAndAuthorizationUsesDiscoveredEndpoint() throws Exception {
        HttpServer issuer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        String origin = "http://127.0.0.1:" + issuer.getAddress().getPort();
        issuer.createContext("/.well-known/openid-configuration", exchange -> {
            byte[] body = MAPPER.writeValueAsBytes(Map.of("issuer", origin,
                    "authorization_endpoint", origin + "/authorize", "token_endpoint", origin + "/token",
                    "userinfo_endpoint", origin + "/userinfo", "jwks_uri", origin + "/jwks"));
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        issuer.start();
        String pool = cognitoJson("CreateUserPool", "{\"PoolName\":\"cfn-idp-proof\"}").path("UserPool").path("Id").asText();
        String stack = "cfn-idp-" + Long.toString(System.nanoTime(), 36);
        boolean created = false;
        try {
            stack("CreateStack", stack, template(pool, "ExampleOidc", origin, "original"));
            created = true;
            assertEquals("CREATE_COMPLETE", CfnStackWaits.awaitTerminal(stack).status());
            String xml = request("DescribeStacks", stack).post("/").then().statusCode(200).extract().asString();
            assertEquals("ExampleOidc", XmlParser.extractPairs(xml, "Outputs", "OutputKey", "OutputValue").get("ProviderRef"));
            assertEquals(origin + "/authorize", provider(pool, "ExampleOidc").path("ProviderDetails").path("authorize_url").asText());
            String client = cognitoJson("CreateUserPoolClient", """
                    {"UserPoolId":"%s","ClientName":"browser","GenerateSecret":false,
                     "CallbackURLs":["http://localhost/callback"],"AllowedOAuthFlows":["code"],
                     "AllowedOAuthScopes":["openid"],"AllowedOAuthFlowsUserPoolClient":true,
                     "SupportedIdentityProviders":["ExampleOidc"]}
                    """.formatted(pool)).path("UserPoolClient").path("ClientId").asText();
            String redirect = given().redirects().follow(false).queryParam("client_id", client)
                    .queryParam("redirect_uri", "http://localhost/callback").queryParam("response_type", "code")
                    .queryParam("scope", "openid").queryParam("identity_provider", "ExampleOidc")
                    .get("/cognito-idp/oauth2/authorize").then().statusCode(302).extract().header("Location");
            assertTrue(redirect.startsWith(origin + "/authorize?"));
            assertTrue(redirect.contains("client_id=original"));

            stack("UpdateStack", stack, template(pool, "ExampleOidc", origin, "updated"));
            assertEquals("UPDATE_COMPLETE", CfnStackWaits.awaitTerminal(stack).status());
            assertEquals("updated", provider(pool, "ExampleOidc").path("ProviderDetails").path("client_id").asText());
            ObjectNode broken = template(pool, "ExampleOidc", origin, "rolled-back");
            ObjectNode dependent = ((ObjectNode) broken.path("Resources")).putObject("Broken");
            dependent.put("Type", "AWS::Cognito::UserPoolClient").put("DependsOn", "Provider");
            dependent.putObject("Properties").put("UserPoolId", "us-east-1_missing");
            stack("UpdateStack", stack, broken);
            assertEquals("UPDATE_ROLLBACK_COMPLETE", CfnStackWaits.awaitTerminal(stack).status());
            assertEquals("updated", provider(pool, "ExampleOidc").path("ProviderDetails").path("client_id").asText());

            stack("UpdateStack", stack, template(pool, "Replacement", origin, "replacement"));
            assertEquals("UPDATE_COMPLETE", CfnStackWaits.awaitTerminal(stack).status());
            cognitoAction("DescribeIdentityProvider", describe(pool, "ExampleOidc")).then().statusCode(400);
            assertEquals("replacement", provider(pool, "Replacement").path("ProviderDetails").path("client_id").asText());
            stack("DeleteStack", stack, null);
            CfnStackWaits.awaitStackDeleted(stack);
            created = false;
            cognitoAction("DescribeIdentityProvider", describe(pool, "Replacement")).then().statusCode(400);
        } finally {
            if (created) {
                stack("DeleteStack", stack, null);
                CfnStackWaits.awaitStackDeleted(stack);
            }
            cognitoAction("DeleteUserPool", "{\"UserPoolId\":\"" + pool + "\"}").then().statusCode(200);
            issuer.stop(0);
        }
    }

    @Test
    void invalidDiscoveryMetadataRollsBackStackWithoutCreatingProvider() throws Exception {
        HttpServer issuer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        issuer.createContext("/", exchange -> {
            byte[] body = "{\"issuer\":\"https://foreign.example.test\"}".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        issuer.start();
        String pool = cognitoJson("CreateUserPool", "{\"PoolName\":\"cfn-invalid-idp\"}").path("UserPool").path("Id").asText();
        String stack = "cfn-invalid-idp-" + Long.toString(System.nanoTime(), 36);
        try {
            stack("CreateStack", stack, template(pool, "ExampleOidc", "http://127.0.0.1:" + issuer.getAddress().getPort(), "synthetic"));
            assertEquals("ROLLBACK_COMPLETE", CfnStackWaits.awaitTerminal(stack).status());
            cognitoAction("DescribeIdentityProvider", describe(pool, "ExampleOidc")).then().statusCode(400);
        } finally {
            stack("DeleteStack", stack, null);
            CfnStackWaits.awaitStackDeleted(stack);
            cognitoAction("DeleteUserPool", "{\"UserPoolId\":\"" + pool + "\"}");
            issuer.stop(0);
        }
    }

    private static ObjectNode template(String pool, String provider, String issuer, String client) {
        ObjectNode template = MAPPER.createObjectNode();
        ObjectNode resource = template.putObject("Resources").putObject("Provider");
        resource.put("Type", "AWS::Cognito::UserPoolIdentityProvider");
        ObjectNode properties = resource.putObject("Properties");
        properties.put("UserPoolId", pool).put("ProviderName", provider).put("ProviderType", "OIDC");
        properties.putObject("ProviderDetails").put("oidc_issuer", issuer).put("client_id", client)
                .put("client_secret", "synthetic-secret").put("authorize_scopes", "openid");
        properties.putObject("AttributeMapping").put("email", "email");
        properties.putArray("IdpIdentifiers").add("synthetic-provider");
        template.putObject("Outputs").putObject("ProviderRef").putObject("Value").put("Ref", "Provider");
        return template;
    }

    private static String describe(String pool, String provider) throws Exception {
        return MAPPER.writeValueAsString(Map.of("UserPoolId", pool, "ProviderName", provider));
    }

    private static JsonNode provider(String pool, String provider) throws Exception {
        return cognitoJson("DescribeIdentityProvider", describe(pool, provider)).path("IdentityProvider");
    }

    private static RequestSpecification request(String action, String stack) {
        return given().contentType("application/x-www-form-urlencoded").header("Authorization", AUTH)
                .formParam("Action", action).formParam("StackName", stack);
    }

    private static void stack(String action, String stack, ObjectNode template) {
        RequestSpecification request = request(action, stack);
        if (template != null) {
            request.formParam("TemplateBody", template.toString());
        }
        request.post("/").then().statusCode(200);
    }
}
