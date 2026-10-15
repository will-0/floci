package io.github.hectorvent.floci.services.ec2;

import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.api.async.ResultCallback;
import com.github.dockerjava.api.model.Frame;
import io.github.hectorvent.floci.config.FlociCertificateAuthority;
import io.github.hectorvent.floci.config.SelfSignedTlsProfile;
import io.github.hectorvent.floci.core.common.dns.EmbeddedDnsServer;
import io.github.hectorvent.floci.core.common.docker.ContainerBuilder;
import io.github.hectorvent.floci.core.common.docker.ContainerLifecycleManager;
import io.github.hectorvent.floci.core.common.docker.ContainerStorageHelper;
import io.github.hectorvent.floci.services.ec2.model.IpPermission;
import io.github.hectorvent.floci.services.ec2.model.UserIdGroupPair;
import io.github.hectorvent.floci.services.elasticache.ElastiCacheServerlessService;
import io.github.hectorvent.floci.services.elasticache.model.ServerlessCache;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * With Floci's TLS on, a serverless cache in its VPC speaks only TLS under a certificate from
 * Floci's CA for its endpoint name: a Node client in the VPC verifies it by that name through
 * {@code NODE_EXTRA_CA_CERTS}, and so does a host client through the proxy port.
 */
@QuarkusTest
@TestProfile(SelfSignedTlsProfile.class)
class VpcServerlessCacheTlsDockerIntegrationTest {

    private static final String REGION = "us-east-1";
    private static final String PING = "*1\r\n$4\r\nPING\r\n";

    @Inject Ec2Service ec2;
    @Inject ElastiCacheServerlessService serverless;
    @Inject VpcAttachments vpc;
    @Inject EmbeddedDnsServer dns;
    @Inject ContainerLifecycleManager lifecycle;
    @Inject ContainerBuilder builder;
    @Inject DockerClient docker;
    @Inject FlociCertificateAuthority ca;

    @Test
    void clientsVerifyTheCacheByItsEndpointName() throws Exception {
        // Containers resolve the endpoint through Floci's DNS, which runs only when Floci is in Docker.
        Assumptions.assumeTrue(vpc.enabled() && dns.getServerIp().isPresent());
        try {
            Assumptions.assumeTrue("linux".equalsIgnoreCase(docker.infoCmd().exec().getOsType()));
        } catch (Exception e) {
            Assumptions.abort("Docker daemon is unavailable");
        }
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String vpcId = ec2.createVpc(REGION, "10.43.0.0/16", false).getVpcId();
        String subnet = ec2.createSubnet(REGION, vpcId, "10.43.1.0/24", REGION + "a").getSubnetId();
        String app = ec2.createSecurityGroup(REGION, "app-" + suffix, "app", vpcId).getGroupId();
        String cacheGroup = ec2.createSecurityGroup(REGION, "cache-" + suffix, "cache", vpcId).getGroupId();
        ec2.authorizeSecurityGroupIngress(REGION, cacheGroup, List.of(tcpFrom(app, 6379)));

        String cacheName = "tls-" + suffix;
        VpcAttachments.Attachment client = null;
        String worker = null;
        ServerlessCache cache = null;
        try {
            cache = serverless.createServerlessCache(new ElastiCacheServerlessService.CreateServerlessCacheRequest(
                    cacheName, "valkey", null, null, List.of(subnet), List.of(cacheGroup), null, null, null, null,
                    null, null, Map.of()));
            String name = cache.getEndpoint().address();
            client = vpc.attach("lambda", app, "000000000000", REGION, subnet, List.of(app), "client", true,
                    Optional.empty(), Map.of(), Map.of(), null);
            worker = lifecycle.createAndStart(builder.newContainer("public.ecr.aws/lambda/nodejs:22")
                    .withName("floci-cache-tls-test-" + suffix)
                    .withNetworkMode(client.networkMode())
                    .withLabels(Map.of(ContainerStorageHelper.SECURITY_GROUP_WORKLOAD_LABEL, "true"))
                    .withEntrypoint(List.of("sleep"))
                    .withCmd(List.of("600"))
                    .build()).containerId();

            assertEquals("+PONG", nodePing(worker, name, 6379));
            assertEquals("+PONG", hostPing(name, cache.getEndpoint().port()));
        } finally {
            if (worker != null) {
                lifecycle.removeIfExists(worker);
            }
            if (client != null) {
                vpc.detach(REGION, client.eni().getNetworkInterfaceId());
            }
            if (cache != null) {
                serverless.deleteServerlessCache(cacheName);
            }
        }
    }

    /** What a Node TLS client with default verification reads back for PING, or its error. */
    private String nodePing(String worker, String host, int port) throws Exception {
        String script = "const [h,p]=process.argv.slice(1);"
                + "const s=require('tls').connect({host:h,port:+p,servername:h},()=>s.write(" + jsString(PING) + "));"
                + "s.on('data',d=>{console.log(String(d).trim());s.end()});"
                + "s.on('error',e=>{console.log(e.message);process.exitCode=1})";
        String id = docker.execCreateCmd(worker).withAttachStdout(true).withAttachStderr(true)
                .withCmd("node", "-e", script, host, String.valueOf(port)).exec().getId();
        StringBuilder out = new StringBuilder();
        try (ResultCallback.Adapter<Frame> callback = new ResultCallback.Adapter<>() {
            @Override
            public void onNext(Frame frame) {
                out.append(new String(frame.getPayload(), StandardCharsets.UTF_8));
            }
        }) {
            docker.execStartCmd(id).exec(callback).awaitCompletion(30, TimeUnit.SECONDS);
        }
        return out.toString().trim();
    }

    /** PING through the proxy port on this host, verifying the certificate for {@code name} against Floci's CA. */
    private String hostPing(String name, int port) throws Exception {
        KeyStore anchors = KeyStore.getInstance("PKCS12");
        anchors.load(null, null);
        anchors.setCertificateEntry("floci", ca.certificate());
        TrustManagerFactory trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trust.init(anchors);
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, trust.getTrustManagers(), null);
        try (Socket plain = new Socket("127.0.0.1", port);
             SSLSocket socket = (SSLSocket) context.getSocketFactory().createSocket(plain, name, port, true)) {
            SSLParameters parameters = socket.getSSLParameters();
            parameters.setEndpointIdentificationAlgorithm("HTTPS");
            socket.setSSLParameters(parameters);
            socket.setSoTimeout(10_000);
            socket.getOutputStream().write(PING.getBytes(StandardCharsets.UTF_8));
            return new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8)).readLine();
        }
    }

    private static String jsString(String value) {
        return "'" + value.replace("\r", "\\r").replace("\n", "\\n") + "'";
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
