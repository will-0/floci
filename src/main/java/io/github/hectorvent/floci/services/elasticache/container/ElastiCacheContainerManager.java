package io.github.hectorvent.floci.services.elasticache.container;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.config.FlociCertificateAuthority;
import io.github.hectorvent.floci.core.common.Pem;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.core.common.docker.ContainerBuilder;
import io.github.hectorvent.floci.core.common.docker.ContainerDetector;
import io.github.hectorvent.floci.core.common.docker.ContainerLifecycleManager;
import io.github.hectorvent.floci.core.common.docker.ContainerLifecycleManager.ContainerInfo;
import io.github.hectorvent.floci.core.common.docker.ContainerLifecycleManager.EndpointInfo;
import io.github.hectorvent.floci.core.common.docker.ContainerLogStreamer;
import io.github.hectorvent.floci.core.common.docker.ContainerSpec;
import io.github.hectorvent.floci.core.common.docker.ContainerStorageHelper;
import io.github.hectorvent.floci.services.acm.CertificateGenerator;
import io.github.hectorvent.floci.services.acm.model.KeyAlgorithm;
import io.github.hectorvent.floci.services.ec2.VpcAttachments;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream;
import org.jboss.logging.Logger;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Stream;

/**
 * Manages backend Docker container lifecycle for ElastiCache replication groups.
 * In native (dev) mode, binds container port 6379 to a random host port.
 * In Docker mode, uses the container's internal network IP directly.
 */
@ApplicationScoped
public class ElastiCacheContainerManager {

    private static final Logger LOG = Logger.getLogger(ElastiCacheContainerManager.class);
    private static final int BACKEND_PORT = 6379;

    /**
     * Docker can publish a host port before Valkey inside the container is listening. Without a probe,
     * the auth proxy may connect, forward PING, and block on PONG until the client times out.
     */
    private static final int BACKEND_READY_DEADLINE_MS = 60_000;
    private static final int BACKEND_READY_RETRY_MS = 100;
    private static final int BACKEND_PROBE_CONNECT_MS = 2_000;
    private static final byte[] RESP_PING = "*1\r\n$4\r\nPING\r\n".getBytes(StandardCharsets.UTF_8);

    private final ContainerBuilder containerBuilder;
    private final ContainerLifecycleManager lifecycleManager;
    private final ContainerLogStreamer logStreamer;
    private final ContainerDetector containerDetector;
    private final EmulatorConfig config;
    private final RegionResolver regionResolver;
    private final Map<String, ElastiCacheContainerHandle> activeContainers = new ConcurrentHashMap<>();
    private volatile boolean dockerUnavailableLogged;
    @Inject
    Instance<VpcAttachments> vpcAttachments;
    private final Map<String, VpcPlacement> vpcPlacements = new ConcurrentHashMap<>();
    private final Map<String, Runnable> vpcDetachers = new ConcurrentHashMap<>();
    @Inject
    Instance<FlociCertificateAuthority> certificateAuthority;
    private final Map<String, String> tlsHosts = new ConcurrentHashMap<>();

    /** A backend's subnet and security groups, and the proxy port its in-VPC clients may also use. */
    public record VpcPlacement(String subnetId, List<String> securityGroupIds, int proxyPort) {}

    @Inject
    public ElastiCacheContainerManager(ContainerBuilder containerBuilder,
                                       ContainerLifecycleManager lifecycleManager,
                                       ContainerLogStreamer logStreamer,
                                       ContainerDetector containerDetector,
                                       EmulatorConfig config,
                                       RegionResolver regionResolver) {
        this.containerBuilder = containerBuilder;
        this.lifecycleManager = lifecycleManager;
        this.logStreamer = logStreamer;
        this.containerDetector = containerDetector;
        this.config = config;
        this.regionResolver = regionResolver;
    }

    /**
     * Attempts {@link #start} and reports the backend as unavailable instead of propagating the
     * failure, when the cause is that no Docker daemon is reachable from Floci: Floci running
     * inside Docker without a mounted socket, or a stopped daemon on the host. A failure raised
     * while the daemon <em>is</em> reachable is a genuine container problem and still propagates,
     * so nothing changes for a Floci that can start Valkey containers.
     *
     * @return the container handle, or {@code null} when no Docker daemon is reachable and no
     *         container was created
     */
    public ElastiCacheContainerHandle tryStart(String groupId, String image, String region) {
        try {
            ElastiCacheContainerHandle handle = start(groupId, image, region);
            dockerUnavailableLogged = false;
            return handle;
        } catch (RuntimeException e) {
            if (isDockerReachable()) {
                throw e;
            }
            boolean partial = activeContainers.containsKey(groupId);
            stopByGroupId(groupId);
            if (partial) {
                throw e;
            }
            if (!dockerUnavailableLogged) {
                dockerUnavailableLogged = true;
                LOG.warnv("No Docker daemon is reachable from Floci ({0}). ElastiCache metadata "
                        + "operations keep working and replication groups still reach 'available', "
                        + "but they have no backing Valkey container until a daemon becomes "
                        + "reachable.", e.getMessage());
            }
            return null;
        }
    }

    /**
     * Probes the configured Docker endpoint, which is how a missing daemon is told apart from a
     * container that failed for its own reasons.
     */
    public boolean isDockerReachable() {
        try {
            lifecycleManager.getDockerClient().pingCmd().exec();
            return true;
        } catch (Exception e) {
            LOG.debugv("Docker daemon is not reachable: {0}", e.getMessage());
            return false;
        }
    }

    public ElastiCacheContainerHandle start(String groupId, String image, String region) {
        return start(groupId, image, List.of(), region);
    }

    /**
     * Starts a backend container for the given resource id, appending {@code extraServerFlags}
     * to the Valkey server command line (via the image's {@code VALKEY_EXTRA_FLAGS} hook).
     * Cluster-mode nodes use this to pass {@code --cluster-enabled} and announce settings.
     */
    public ElastiCacheContainerHandle start(String groupId, String image, List<String> extraServerFlags,
                                            String region) {
        LOG.infov("Starting ElastiCache backend container for group: {0}", groupId);

        String containerName = containerName(groupId);

        // Remove any stale container with the same name
        lifecycleManager.removeIfExists(containerName);

        StringBuilder serverFlags = new StringBuilder("--loglevel verbose");
        for (String flag : extraServerFlags) {
            serverFlags.append(' ').append(flag);
        }
        String tlsHost = tlsHosts.get(groupId);
        CertificateGenerator.GeneratedCertificate certificate = tlsHost == null || !config.tls().enabled() ? null
                : certificateAuthority.get().issueServerCertificate("localhost",
                        Stream.of(tlsHost, "localhost").distinct().toList(), KeyAlgorithm.EC_prime256v1, null);
        SSLContext tls = certificate == null ? null : sslContext(certificate);
        if (certificate != null) {
            serverFlags.append(" --port 0 --tls-port ").append(BACKEND_PORT).append(" --tls-auth-clients no")
                    .append(" --tls-cert-file /floci-tls/server.crt --tls-key-file /floci-tls/server.key");
        }

        // Build container spec. Only publish the backend port to the host in
        // native mode — in Docker mode the JVM reaches the container via its
        // network IP, no host binding needed.
        ContainerBuilder.Builder specBuilder = containerBuilder.newContainer(image)
                .withName(containerName)
                .withEnv("VALKEY_EXTRA_FLAGS", serverFlags.toString())
                .withDockerNetwork(config.services().elasticache().dockerNetwork())
                .withLogRotation()
                .withLabels(ContainerStorageHelper.resourceIdentityLabels(
                        "elasticache", groupId, regionResolver.getAccountId(), region));

        VpcPlacement placement = vpcEnabled() ? vpcPlacements.get(groupId) : null;
        VpcAttachments.Attachment attachment = placement != null
                ? joinVpc(specBuilder, placement, groupId, containerName, region) : null;
        if (attachment == null && !containerDetector.isRunningInContainer()) {
            specBuilder.withDynamicPort(BACKEND_PORT);
        } else if (attachment == null) {
            specBuilder.withExposedPort(BACKEND_PORT);
        }

        ContainerSpec spec = specBuilder.build();

        // Create and start container
        ContainerInfo info;
        try {
            info = certificate == null ? lifecycleManager.createAndStart(spec) : startWithCertificate(spec, certificate);
        } catch (RuntimeException e) {
            detachVpc(groupId);
            throw e;
        }
        // A backend in its VPC listens in the namespace, which publishes its ports.
        EndpointInfo endpoint = attachment != null
                ? lifecycleManager.resolveEndpoint(attachment.helperId(), BACKEND_PORT) : info.getEndpoint(BACKEND_PORT);

        LOG.infov("ElastiCache backend for group {0}: {1}", groupId, endpoint);

        ElastiCacheContainerHandle handle = new ElastiCacheContainerHandle(
                info.containerId(), groupId, endpoint.host(), endpoint.port());
        try {
            handle.setNetworkIp(lifecycleManager.resolveContainerNetworkIp(
                    info.containerId(), config.services().elasticache().dockerNetwork().orElse(null)));
        } catch (RuntimeException e) {
            LOG.warnv("Could not resolve network IP for ElastiCache container {0}: {1}",
                    info.containerId(), e.getMessage());
        }
        handle.setTls(tls);
        activeContainers.put(groupId, handle);

        // Attach log streaming
        String shortId = info.containerId().length() >= 8
                ? info.containerId().substring(0, 8)
                : info.containerId();
        String logGroup = "/aws/elasticache/cluster/" + groupId + "/engine-log";
        String logStream = logStreamer.generateLogStreamName(shortId);

        Closeable logHandle = logStreamer.attach(
                info.containerId(), logGroup, logStream, region, "elasticache:" + groupId);
        handle.setLogStream(logHandle);

        waitForBackendReady(groupId, endpoint.host(), endpoint.port(), tls);

        return handle;
    }

    /**
     * Whether the group's next backend speaks TLS alone, as a serverless cache does on AWS, under a
     * leaf from Floci's CA for {@code host}. Null, or Floci's TLS off, keeps it on plaintext.
     */
    public void serveTls(String groupId, String host) {
        if (host == null) {
            tlsHosts.remove(groupId);
        } else {
            tlsHosts.put(groupId, host);
        }
    }

    private ContainerInfo startWithCertificate(ContainerSpec spec, CertificateGenerator.GeneratedCertificate certificate) {
        String containerId = lifecycleManager.create(spec);
        try (ByteArrayOutputStream archive = new ByteArrayOutputStream()) {
            try (TarArchiveOutputStream tar = new TarArchiveOutputStream(archive)) {
                // Default mode 0644: Valkey reads the key as its own user, and the key covers this cache alone.
                for (Map.Entry<String, String> file : Map.of("floci-tls/server.crt", certificate.certificatePem(),
                        "floci-tls/server.key", certificate.privateKeyPem()).entrySet()) {
                    byte[] content = file.getValue().getBytes(StandardCharsets.UTF_8);
                    TarArchiveEntry entry = new TarArchiveEntry(file.getKey());
                    entry.setSize(content.length);
                    tar.putArchiveEntry(entry);
                    tar.write(content);
                    tar.closeArchiveEntry();
                }
            }
            lifecycleManager.getDockerClient().copyArchiveToContainerCmd(containerId).withRemotePath("/")
                    .withTarInputStream(new ByteArrayInputStream(archive.toByteArray())).exec();
        } catch (IOException e) {
            throw new IllegalStateException("Failed to install a TLS certificate into " + containerId, e);
        }
        return lifecycleManager.startCreated(containerId, spec);
    }

    /** Serves the cache's leaf and trusts Floci's CA, for the proxy and the readiness probe alike. */
    private SSLContext sslContext(CertificateGenerator.GeneratedCertificate certificate) {
        try {
            X509Certificate ca = certificateAuthority.get().certificate();
            KeyStore store = KeyStore.getInstance("PKCS12");
            store.load(null, null);
            store.setKeyEntry("cache", Pem.parsePrivateKey(certificate.privateKeyPem()), new char[0],
                    new Certificate[] {Pem.parseCertificate(certificate.certificatePem()), ca});
            store.setCertificateEntry("ca", ca);
            KeyManagerFactory keys = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keys.init(store, new char[0]);
            TrustManagerFactory trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trust.init(store);
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(keys.getKeyManagers(), trust.getTrustManagers(), null);
            return context;
        } catch (GeneralSecurityException | IOException e) {
            throw new IllegalStateException("Failed to build the TLS context of a cache certificate", e);
        }
    }

    private static void waitForBackendReady(String groupId, String host, int port, SSLContext tls) {
        long deadline = System.currentTimeMillis() + BACKEND_READY_DEADLINE_MS;
        int attempt = 0;
        while (System.currentTimeMillis() < deadline) {
            attempt++;
            try (Socket s = tls == null ? new Socket() : tls.getSocketFactory().createSocket()) {
                s.connect(new InetSocketAddress(host, port), BACKEND_PROBE_CONNECT_MS);
                s.setTcpNoDelay(true);
                s.setSoTimeout(BACKEND_PROBE_CONNECT_MS);
                OutputStream out = s.getOutputStream();
                out.write(RESP_PING);
                out.flush();
                String line = RespLineReader.readAsciiLineCrLf(s.getInputStream());
                if (line.startsWith("+PONG")) {
                    if (attempt > 1) {
                        LOG.infov("ElastiCache backend ready for group {0} after {1} probe attempt(s)", groupId, attempt);
                    }
                    return;
                }
                if (LOG.isDebugEnabled()) {
                    LOG.debugv("ElastiCache backend probe for group {0}: unexpected line {1}", groupId, line);
                }
            } catch (IOException e) {
                if (LOG.isDebugEnabled()) {
                    LOG.debugv("ElastiCache backend probe for group {0} attempt {1}: {2}", groupId, attempt, e.getMessage());
                }
            }
            try {
                Thread.sleep(BACKEND_READY_RETRY_MS);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                throw new RuntimeException("Interrupted while waiting for ElastiCache backend " + groupId, ie);
            }
        }
        throw new RuntimeException(
                "ElastiCache backend for group " + groupId + " did not become ready on " + host + ":" + port
                        + " within " + BACKEND_READY_DEADLINE_MS + "ms");
    }

    public void stop(ElastiCacheContainerHandle handle) {
        if (handle == null) {
            return;
        }
        ElastiCacheContainerHandle existing = activeContainers.remove(handle.getGroupId());
        Closeable logStream = handle.getLogStream() != null ? handle.getLogStream()
                : (existing != null ? existing.getLogStream() : null);
        lifecycleManager.stopAndRemove(handle.getContainerId(), logStream);
        detachVpc(handle.getGroupId());
    }

    public boolean vpcEnabled() {
        return vpcAttachments != null && vpcAttachments.isResolvable() && vpcAttachments.get().enabled();
    }

    /** Where the group's next backend runs: in its VPC, or on Floci's Docker network when null. */
    public void placeInVpc(String groupId, VpcPlacement placement) {
        if (placement == null) {
            vpcPlacements.remove(groupId);
        } else {
            vpcPlacements.put(groupId, placement);
        }
    }

    /**
     * Runs the backend in a protected namespace on its subnet, behind its security groups, as
     * ElastiCache puts a cache's ENI there. In-VPC clients reach Valkey on 6379 or on the proxy
     * port the endpoint advertises.
     */
    private VpcAttachments.Attachment joinVpc(ContainerBuilder.Builder spec, VpcPlacement placement,
                                              String groupId, String containerName, String region) {
        VpcAttachments vpc = vpcAttachments.get();
        VpcAttachments.Attachment attachment = vpc.attach("elasticache", containerName,
                regionResolver.getAccountId(), region, placement.subnetId(), placement.securityGroupIds(),
                "ElastiCache " + groupId, true, config.services().elasticache().dockerNetwork(),
                containerDetector.isRunningInContainer() ? Map.of() : Map.of(BACKEND_PORT, 0), Map.of(), null);
        vpcDetachers.put(groupId, () -> vpc.detach(region, attachment.eni().getNetworkInterfaceId()));
        if (placement.proxyPort() != BACKEND_PORT) {
            vpc.redirect(attachment, placement.proxyPort(), BACKEND_PORT);
        }
        spec.withNetworkMode(attachment.networkMode())
                .withLabels(Map.of(ContainerStorageHelper.SECURITY_GROUP_WORKLOAD_LABEL, "true"));
        return attachment;
    }

    private void detachVpc(String groupId) {
        Runnable detach = vpcDetachers.remove(groupId);
        if (detach != null) {
            detach.run();
        }
    }

    /**
     * Stops and removes the backend container for a group by id, if one exists.
     * Used by the service's provisioning rollback: {@link #start} registers the container in
     * {@code activeContainers} <em>before</em> {@link #waitForBackendReady}, so a readiness
     * timeout throws without ever returning the handle to the caller. In that case rollback
     * can't go through {@link #stop} (it has no handle), so it cleans up by id instead. Falls
     * back to the deterministic container name to catch a container that failed before it was
     * registered. Idempotent — a no-op when nothing is running for the id.
     */
    public void stopByGroupId(String groupId) {
        ElastiCacheContainerHandle handle = activeContainers.get(groupId);
        if (handle != null) {
            stop(handle);
            return;
        }
        lifecycleManager.removeIfExists(containerName(groupId));
        detachVpc(groupId);
    }

    private String containerName(String groupId) {
        return ContainerStorageHelper.resourceName(config, "valkey", null, groupId);
    }

    public void stopAll() {
        List<ElastiCacheContainerHandle> handles = new ArrayList<>(activeContainers.values());
        if (!handles.isEmpty()) {
            LOG.infov("Stopping {0} ElastiCache container(s) on shutdown", handles.size());
        }
        for (ElastiCacheContainerHandle handle : handles) {
            stop(handle);
        }
    }
}
