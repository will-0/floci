package io.github.hectorvent.floci.services.cloudfront;

import com.sun.net.httpserver.HttpServer;
import io.github.hectorvent.floci.services.cloudfront.model.DefaultCacheBehavior;
import io.github.hectorvent.floci.services.cloudfront.model.Distribution;
import io.github.hectorvent.floci.services.cloudfront.model.DistributionConfig;
import io.github.hectorvent.floci.services.cloudfront.model.Origin;
import io.github.hectorvent.floci.services.elbv2.ElbV2Service;
import io.github.hectorvent.floci.services.elbv2.model.Action;
import io.github.hectorvent.floci.services.elbv2.model.LoadBalancer;
import io.github.hectorvent.floci.services.elbv2.model.TargetDescription;
import io.github.hectorvent.floci.services.elbv2.model.TargetGroup;
import io.github.hectorvent.floci.services.route53.Route53Service;
import io.github.hectorvent.floci.services.route53.model.AliasTarget;
import io.github.hectorvent.floci.services.route53.model.ResourceRecordSet;
import io.github.hectorvent.floci.testing.RealElbV2DataPlaneProfile;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;

@QuarkusTest
@TestProfile(RealElbV2DataPlaneProfile.class)
class CloudFrontNativeAlbIntegrationTest {
    @Inject ElbV2Service elb;
    @Inject Route53Service route53;
    @Inject CloudFrontService cloudfront;

    @Test
    void cloudFrontReachesNativeHttpsListenerThroughProvisionedAlias() throws Exception {
        int port;
        try (ServerSocket socket = new ServerSocket(0)) {
            port = socket.getLocalPort();
        }
        String suffix = Long.toString(System.nanoTime(), 36);
        String alias = "origin-" + suffix + ".example.test";
        LoadBalancer lb = elb.createLoadBalancer("us-east-1", "cf-native-" + suffix,
                "internet-facing", "application", "ipv4", List.of(), List.of(), Map.of());
        String certificate = given().header("X-Amz-Target", "CertificateManager.RequestCertificate")
                .contentType("application/x-amz-json-1.1").body(("{\"DomainName\":\"" + alias + "\"}").getBytes(StandardCharsets.UTF_8))
                .post("/").then().statusCode(200).extract().path("CertificateArn");
        HttpServer echo = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        echo.createContext("/", exchange -> {
            byte[] body = exchange.getRequestBody().readAllBytes();
            exchange.getResponseHeaders().set("X-Observed-Method", exchange.getRequestMethod());
            exchange.getResponseHeaders().set("X-Observed-Uri", exchange.getRequestURI().toASCIIString());
            exchange.getResponseHeaders().set("X-Observed-Host", exchange.getRequestHeaders().getFirst("Host"));
            exchange.getResponseHeaders().set("X-Observed-Proto", exchange.getRequestHeaders().getFirst("X-Forwarded-Proto"));
            exchange.getResponseHeaders().set("X-Observed-Secret", exchange.getRequestHeaders().getFirst("X-Origin-Secret"));
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        echo.start();
        int targetPort = echo.getAddress().getPort();
        TargetGroup group = elb.createTargetGroup("us-east-1", "cf-echo-" + suffix, "HTTP", "HTTP1",
                targetPort, null, "ip", null, null, false, null, null, null, null, null, null, null, Map.of());
        TargetDescription target = new TargetDescription();
        target.setId("127.0.0.1");
        target.setPort(targetPort);
        elb.registerTargets("us-east-1", group.getTargetGroupArn(), List.of(target));
        elb.modifyLoadBalancerAttributes("us-east-1", lb.getLoadBalancerArn(),
                Map.of("routing.http.preserve_host_header.enabled", "true"));
        Action action = new Action();
        action.setType("forward");
        action.setTargetGroupArn(group.getTargetGroupArn());
        elb.createListener("us-east-1", lb.getLoadBalancerArn(), "HTTPS", port,
                null, List.of(certificate), List.of(action), List.of(), Map.of());
        String zone = route53.createHostedZone("example.test", suffix, null, null).zone().getId();
        ResourceRecordSet record = new ResourceRecordSet();
        record.setName(alias);
        record.setType("A");
        AliasTarget aliasTarget = new AliasTarget();
        aliasTarget.setDnsName(lb.getDnsName());
        aliasTarget.setHostedZoneId("ZELB");
        record.setAliasTarget(aliasTarget);
        route53.changeResourceRecordSets(zone, List.of(Map.of("action", "CREATE", "rrs", record)), null);
        try {
            Origin origin = new Origin();
            origin.setId("native");
            origin.setDomainName(alias);
            origin.setCustomHeaders(List.of(Map.of("HeaderName", "X-Origin-Secret", "HeaderValue", "synthetic-proof")));
            origin.setCustomOriginConfig(Map.of("OriginProtocolPolicy", "https-only", "HTTPSPort", port));
            DefaultCacheBehavior behavior = new DefaultCacheBehavior();
            behavior.setTargetOriginId("native");
            behavior.setViewerProtocolPolicy("allow-all");
            behavior.setAllowedMethods(List.of("GET", "HEAD", "POST"));
            behavior.setForwardedValues(Map.of("QueryString", true));
            DistributionConfig config = new DistributionConfig();
            config.setEnabled(true);
            config.setOrigins(List.of(origin));
            config.setDefaultCacheBehavior(behavior);
            Distribution distribution = new Distribution();
            distribution.setConfig(config);
            distribution = cloudfront.createDistribution(distribution, Map.of());
            given().urlEncodingEnabled(false).header("Host", distribution.getDomainName())
                    .contentType("text/plain").body("synthetic request body")
                    .post("/encoded%2Fpath?item=one%2Btwo&item=three")
                    .then().statusCode(200).body(equalTo("synthetic request body"))
                    .header("X-Observed-Method", equalTo("POST"))
                    .header("X-Observed-Uri", equalTo("/encoded%2Fpath?item=one%2Btwo&item=three"))
                    .header("X-Observed-Host", equalTo(alias + ":" + port))
                    .header("X-Observed-Proto", equalTo("https"))
                    .header("X-Observed-Secret", equalTo("synthetic-proof"));
        } finally {
            elb.deleteLoadBalancer("us-east-1", lb.getLoadBalancerArn());
            elb.deleteTargetGroup("us-east-1", group.getTargetGroupArn());
            echo.stop(0);
        }
    }
}
