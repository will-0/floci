package io.github.hectorvent.floci.services.lambda;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.dockerjava.api.DockerClient;
import io.github.hectorvent.floci.config.SelfSignedTlsProfile;
import io.github.hectorvent.floci.core.common.dns.EmbeddedDnsServer;
import io.github.hectorvent.floci.services.ec2.Ec2Service;
import io.github.hectorvent.floci.services.ec2.VpcAttachments;
import io.github.hectorvent.floci.services.ec2.model.IpPermission;
import io.github.hectorvent.floci.services.ec2.model.UserIdGroupPair;
import io.github.hectorvent.floci.services.rds.RdsService;
import io.github.hectorvent.floci.services.rds.model.DbCluster;
import io.github.hectorvent.floci.services.rds.model.DbInstance;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

/**
 * With Floci's TLS on, a VPC Lambda that trusts only {@code /var/runtime/ca-cert.pem}, as functions
 * do on AWS to verify RDS, verifies an Aurora Postgres backend by its writer, reader and member
 * instance endpoint names, and still refuses a name the certificate does not cover.
 */
@QuarkusTest
@TestProfile(SelfSignedTlsProfile.class)
class LambdaVpcRdsTlsDockerIntegrationTest {

    private static final String REGION = "us-east-1";
    private static final String BASE_PATH = "/2015-03-31";

    @Inject Ec2Service ec2;
    @Inject RdsService rds;
    @Inject VpcAttachments vpc;
    @Inject EmbeddedDnsServer dns;
    @Inject DockerClient docker;

    @Test
    void vpcLambdaVerifiesPostgresByEndpointName() throws Exception {
        // Containers resolve the endpoint through Floci's DNS, which runs only when Floci is in Docker.
        Assumptions.assumeTrue(vpc.enabled() && dns.getServerIp().isPresent());
        try {
            Assumptions.assumeTrue("linux".equalsIgnoreCase(docker.infoCmd().exec().getOsType()));
        } catch (Exception e) {
            Assumptions.abort("Docker daemon is unavailable");
        }
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String vpcId = ec2.createVpc(REGION, "10.44.0.0/16", false).getVpcId();
        String subnet = ec2.createSubnet(REGION, vpcId, "10.44.1.0/24", REGION + "a").getSubnetId();
        String app = ec2.createSecurityGroup(REGION, "app-" + suffix, "app", vpcId).getGroupId();
        String db = ec2.createSecurityGroup(REGION, "db-" + suffix, "db", vpcId).getGroupId();
        ec2.authorizeSecurityGroupIngress(REGION, db, List.of(tcpFrom(app, 5432)));
        rds.createDbSubnetGroup("db-" + suffix, "db", List.of(subnet), REGION);

        String clusterId = "tls-" + suffix;
        String memberId = clusterId + "-1";
        String functionName = "rds-tls-" + suffix;
        try {
            DbCluster cluster = rds.createDbCluster(clusterId, "aurora-postgresql", "17.4", "app", "secret-password",
                    "app", false, null, "db-" + suffix, null, false, REGION, null, null, null, false, null,
                    null, false, null, List.of(db));
            DbInstance member = rds.createDbInstance(memberId, "aurora-postgresql", "17.4", null, null, null,
                    "db.r6g.large", 0, false, null, "db-" + suffix, clusterId);
            String writer = cluster.getEndpoint().address();
            String reader = cluster.getReaderEndpoint().address();
            String instance = member.getEndpoint().address();
            String address = cluster.getContainerHost();

            given().contentType("application/json")
                    .body("""
                        {
                          "FunctionName": "%1$s",
                          "Runtime": "nodejs22.x",
                          "Role": "arn:aws:iam::000000000000:role/lambda",
                          "Handler": "index.handler",
                          "Timeout": 60,
                          "Code": {"ZipFile": "%2$s"},
                          "VpcConfig": {"SubnetIds": ["%3$s"], "SecurityGroupIds": ["%4$s"]},
                          "Environment": {"Variables": {"NODE_EXTRA_CA_CERTS": "/var/runtime/ca-cert.pem"}}
                        }
                        """.formatted(functionName, handlerZipBase64(), subnet, app))
                    .when().post(BASE_PATH + "/functions")
                    .then().statusCode(201);

            String body = given().contentType("application/json")
                    .body(new ObjectMapper().writeValueAsString(Map.of("hosts", List.of(writer, reader, instance, address))))
                    .when().post(BASE_PATH + "/functions/" + functionName + "/invocations")
                    .then().statusCode(200).extract().asString();
            Map<String, String> results = new ObjectMapper().readValue(body, new TypeReference<>() {});

            assertEquals("verified", results.get(writer), body);
            assertEquals("verified", results.get(reader), body);
            assertEquals("verified", results.get(instance), body);
            // The backend's bare address is not a name the certificate covers.
            assertNotEquals("verified", results.get(address), body);
        } finally {
            given().when().delete(BASE_PATH + "/functions/" + functionName);
            rds.deleteDbInstance(memberId, REGION);
            rds.deleteDbCluster(clusterId, REGION);
        }
    }

    /** Postgres's SSLRequest, then a TLS handshake with Node's default verification, per host. */
    private static String handlerZipBase64() throws Exception {
        String handler = """
                const net = require('net');
                const tls = require('tls');

                const probe = (host) => new Promise((resolve) => {
                  const raw = net.connect(5432, host, () => {
                    const request = Buffer.alloc(8);
                    request.writeInt32BE(8, 0);
                    request.writeInt32BE(80877103, 4);
                    raw.write(request);
                  });
                  raw.setTimeout(10000, () => { raw.destroy(); resolve('timeout'); });
                  raw.on('error', (e) => resolve(e.message));
                  raw.once('data', (answer) => {
                    if (String(answer) !== 'S') { raw.destroy(); return resolve('no TLS'); }
                    const secure = tls.connect({ socket: raw, servername: host }, () => {
                      secure.destroy();
                      resolve('verified');
                    });
                    secure.on('error', (e) => resolve(e.message));
                  });
                });

                exports.handler = async (event) =>
                  Object.fromEntries(await Promise.all(event.hosts.map(async (h) => [h, await probe(h)])));
                """;
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(bytes)) {
            zip.putNextEntry(new ZipEntry("index.js"));
            zip.write(handler.getBytes(StandardCharsets.UTF_8));
            zip.closeEntry();
        }
        return Base64.getEncoder().encodeToString(bytes.toByteArray());
    }

    private static IpPermission tcpFrom(String groupId, int port) {
        UserIdGroupPair source = new UserIdGroupPair();
        source.setGroupId(groupId);
        source.setUserId("000000000000");
        IpPermission permission = new IpPermission();
        permission.setIpProtocol("tcp");
        permission.setFromPort(port);
        permission.setToPort(port);
        permission.getUserIdGroupPairs().add(source);
        return permission;
    }
}
