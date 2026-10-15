package io.github.hectorvent.floci.services.ec2;

import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.api.async.ResultCallback;
import com.github.dockerjava.api.model.Frame;
import io.github.hectorvent.floci.core.common.dns.EmbeddedDnsServer;
import io.github.hectorvent.floci.core.common.docker.ContainerBuilder;
import io.github.hectorvent.floci.core.common.docker.ContainerLifecycleManager;
import io.github.hectorvent.floci.core.common.docker.ContainerStorageHelper;
import io.github.hectorvent.floci.services.ec2.model.IpPermission;
import io.github.hectorvent.floci.services.ec2.model.UserIdGroupPair;
import io.github.hectorvent.floci.services.elasticache.ElastiCacheService;
import io.github.hectorvent.floci.services.elasticache.model.CacheCluster;
import io.github.hectorvent.floci.services.rds.RdsService;
import io.github.hectorvent.floci.services.rds.model.DbCluster;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** A DB and a cache in their VPC admit only the security group their ingress rules name, at their endpoint names. */
@QuarkusTest
class VpcBackendSecurityGroupDockerIntegrationTest {

    private static final String REGION = "us-east-1";

    @Inject Ec2Service ec2;
    @Inject RdsService rds;
    @Inject ElastiCacheService elastiCache;
    @Inject VpcAttachments vpc;
    @Inject EmbeddedDnsServer dns;
    @Inject ContainerLifecycleManager lifecycle;
    @Inject ContainerBuilder builder;
    @Inject DockerClient docker;

    @Test
    void backendSecurityGroupAdmitsOnlyTheGroupItsRulesName() throws Exception {
        // Containers resolve the endpoint through Floci's DNS, which runs only when Floci is in Docker.
        Assumptions.assumeTrue(vpc.enabled() && dns.getServerIp().isPresent());
        try {
            Assumptions.assumeTrue("linux".equalsIgnoreCase(docker.infoCmd().exec().getOsType()));
        } catch (Exception e) {
            Assumptions.abort("Docker daemon is unavailable");
        }
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String vpcId = ec2.createVpc(REGION, "10.42.0.0/16", false).getVpcId();
        String subnet = ec2.createSubnet(REGION, vpcId, "10.42.1.0/24", REGION + "a").getSubnetId();
        String app = ec2.createSecurityGroup(REGION, "app-" + suffix, "app", vpcId).getGroupId();
        String other = ec2.createSecurityGroup(REGION, "other-" + suffix, "other", vpcId).getGroupId();
        String db = ec2.createSecurityGroup(REGION, "db-" + suffix, "db", vpcId).getGroupId();
        ec2.authorizeSecurityGroupIngress(REGION, db, List.of(tcpFrom(app, 5432), tcpFrom(app, 6379)));
        rds.createDbSubnetGroup("db-" + suffix, "db", List.of(subnet), REGION);
        elastiCache.createCacheSubnetGroup("cache-" + suffix, "cache", List.of(subnet), Map.of());

        List<VpcAttachments.Attachment> clients = new ArrayList<>();
        List<String> workers = new ArrayList<>();
        String clusterId = "db-" + suffix;
        try {
            DbCluster cluster = rds.createDbCluster(clusterId, "aurora-postgresql", "17.4", "app", "secret-password",
                    "app", false, null, "db-" + suffix, null, false, REGION, null, null, null, false, null,
                    null, false, null, List.of(db));
            String name = cluster.getEndpoint().address();
            CacheCluster cache = elastiCache.createCacheCluster(new ElastiCacheService.CreateCacheClusterRequest(
                    "cache-" + suffix, "valkey", null, null, 1, null, null, null, null, "cache-" + suffix,
                    null, null, null, null, List.of(db), null, null, null, REGION, Map.of()));
            String cacheName = cache.getConfigurationEndpoint().address();
            for (String group : List.of(app, other)) {
                VpcAttachments.Attachment client = vpc.attach("lambda", group, "000000000000", REGION, subnet,
                        List.of(group), "client", true, Optional.empty(), Map.of(), Map.of(), null);
                clients.add(client);
                workers.add(lifecycle.createAndStart(builder.newContainer("alpine:3.21")
                        .withName("floci-rds-vpc-test-" + group)
                        .withNetworkMode(client.networkMode())
                        .withLabels(Map.of(ContainerStorageHelper.SECURITY_GROUP_WORKLOAD_LABEL, "true"))
                        .withEntrypoint(List.of("sleep"))
                        .withCmd(List.of("600"))
                        .build()).containerId());
            }

            assertEquals(0, connect(workers.getFirst(), name, 5432, 5));
            assertEquals(0, connect(workers.getFirst(), name, cluster.getEndpoint().port(), 5));
            assertNotEquals(0, connect(workers.get(1), name, 5432, 1));
            assertEquals(0, connect(workers.getFirst(), cacheName, 6379, 5));
            assertNotEquals(0, connect(workers.get(1), cacheName, 6379, 1));

            // Postgres itself speaks TLS to clients that require it.
            try (Connection connection = DriverManager.getConnection("jdbc:postgresql://"
                    + cluster.getContainerHost() + ":" + cluster.getContainerPort() + "/app?sslmode=require",
                    "app", "secret-password");
                 ResultSet ssl = connection.createStatement()
                         .executeQuery("SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()")) {
                assertTrue(ssl.next() && ssl.getBoolean(1));
            }
        } finally {
            workers.forEach(lifecycle::removeIfExists);
            clients.forEach(client -> vpc.detach(REGION, client.eni().getNetworkInterfaceId()));
            rds.deleteDbCluster(clusterId, REGION);
            elastiCache.deleteCacheCluster("cache-" + suffix);
        }
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

    private int connect(String worker, String host, int port, int timeoutSeconds) throws Exception {
        String id = docker.execCreateCmd(worker).withAttachStdout(true).withAttachStderr(true)
                .withCmd("nc", "-z", "-w", String.valueOf(timeoutSeconds), host, String.valueOf(port))
                .exec().getId();
        try (ResultCallback.Adapter<Frame> callback = new ResultCallback.Adapter<>()) {
            docker.execStartCmd(id).exec(callback).awaitCompletion(timeoutSeconds + 5L, TimeUnit.SECONDS);
        }
        return docker.inspectExecCmd(id).exec().getExitCodeLong().intValue();
    }
}
