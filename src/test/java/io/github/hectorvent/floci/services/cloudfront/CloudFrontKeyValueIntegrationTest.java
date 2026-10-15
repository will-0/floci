package io.github.hectorvent.floci.services.cloudfront;

import io.github.hectorvent.floci.core.common.XmlParser;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.response.Response;
import org.junit.jupiter.api.Test;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.*;

@QuarkusTest
class CloudFrontKeyValueIntegrationTest {
    @Test
    void omittedCommentRemainsAbsentForProviderStateConsistency() {
        String name = "no-comment-" + UUID.randomUUID();
        Response created = given().body("<CreateKeyValueStoreRequest><Name>" + name + "</Name></CreateKeyValueStoreRequest>")
                .post("/2020-05-31/key-value-store").then().statusCode(201).extract().response();
        assertNull(XmlParser.extractFirst(created.asString(), "Comment", null));
        Response described = given().get("/2020-05-31/key-value-store/" + name).then().statusCode(200).extract().response();
        assertNull(XmlParser.extractFirst(described.asString(), "Comment", null));
    }

    @Test
    void managementAndDataPlanesShareOptimisticConcurrency() {
        String name = "release-" + UUID.randomUUID();
        Response created = given().body("<CreateKeyValueStoreRequest><Name>" + name + "</Name><Comment>release pointer</Comment></CreateKeyValueStoreRequest>")
                .post("/2020-05-31/key-value-store").then().statusCode(201).extract().response();
        String arn = XmlParser.extractFirst(created.asString(), "ARN", null);
        assertNotNull(arn);
        String store = "/key-value-stores/" + URLEncoder.encode(arn, StandardCharsets.UTF_8);
        Response description = given().urlEncodingEnabled(false).header("Authorization", "AWS4-ECDSA-P256-SHA256 Credential=test/20261015/cloudfront-keyvaluestore/aws4_request, SignedHeaders=host, Signature=test").get(store).then().statusCode(200).extract().response();
        assertTrue(description.jsonPath().get("Created") instanceof Number);
        String before = description.header("ETag");
        Response update = given().urlEncodingEnabled(false).header("If-Match", before).contentType("application/json")
                .body(Map.of("Value", "[{\"v\":\"abcdef123456\"}]"))
                .put(store + "/keys/releases").then().statusCode(200).body("ItemCount", equalTo(1)).extract().response();
        assertNotEquals(before, update.header("ETag"));
        given().urlEncodingEnabled(false).get(store + "/keys/releases").then().statusCode(200)
                .body("Value", equalTo("[{\"v\":\"abcdef123456\"}]"));
        given().urlEncodingEnabled(false).header("If-Match", before).contentType("application/json").body(Map.of("Value", "stale"))
                .put(store + "/keys/releases").then().statusCode(409);
        given().urlEncodingEnabled(false).header("If-Match", update.header("ETag")).contentType("application/json")
                .body(Map.of("Puts", List.of(Map.of("Key", "auth", "Value", "test")),
                        "Deletes", List.of(Map.of("Key", "releases"))))
                .post(store + "/keys").then().statusCode(200).body("ItemCount", equalTo(1));
        given().urlEncodingEnabled(false).get(store + "/keys/releases").then().statusCode(404);
    }
}
