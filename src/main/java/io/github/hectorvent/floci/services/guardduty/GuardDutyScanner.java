package io.github.hectorvent.floci.services.guardduty;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.ContainerTeardown;
import io.github.hectorvent.floci.core.common.Resettable;
import io.github.hectorvent.floci.core.common.docker.ContainerBuilder;
import io.github.hectorvent.floci.core.common.docker.ContainerDetector;
import io.github.hectorvent.floci.core.common.docker.ContainerLifecycleManager;
import io.github.hectorvent.floci.core.common.docker.ContainerStorageHelper;
import io.github.hectorvent.floci.services.guardduty.model.MalwareProtectionPlan;
import io.quarkus.runtime.ShutdownEvent;
import jakarta.annotation.PreDestroy;
import jakarta.annotation.Priority;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.function.Supplier;

@ApplicationScoped
public class GuardDutyScanner implements ContainerTeardown, Resettable {
    private static final Logger LOG = Logger.getLogger(GuardDutyScanner.class);
    private final EmulatorConfig config;
    private final GuardDutyService guardDuty;
    private final ContainerBuilder builder;
    private final ContainerLifecycleManager lifecycle;
    private final ContainerDetector detector;
    private volatile ExecutorService scans = newScanExecutor();
    private volatile ExecutorService transports = Executors.newVirtualThreadPerTaskExecutor();
    private final Set<InputStream> openStreams = ConcurrentHashMap.newKeySet();
    private volatile boolean stopping;
    private volatile long lifecycleGeneration;
    private String containerId;
    private ContainerLifecycleManager.EndpointInfo endpoint;

    @Inject
    public GuardDutyScanner(EmulatorConfig config, GuardDutyService guardDuty, ContainerBuilder builder,
                            ContainerLifecycleManager lifecycle, ContainerDetector detector) {
        this.config = config;
        this.guardDuty = guardDuty;
        this.builder = builder;
        this.lifecycle = lifecycle;
        this.detector = detector;
    }

    public void submit(String account, String region, String bucket, String key, long size,
                       Supplier<InputStream> source, Consumer<String> complete) {
        EmulatorConfig.MalwareScanConfig settings = config.services().guardduty().malwareScan();
        if (!settings.enabled()) {
            return;
        }
        Optional<MalwareProtectionPlan> protection = guardDuty.protectionForObject(account, region, bucket, key);
        if (protection.isEmpty()) {
            return;
        }
        Consumer<String> tag = "ENABLED".equals(protection.get().getTaggingStatus()) ? complete : ignored -> {};
        if (size > settings.maxBytes()) {
            tag.accept("UNSUPPORTED");
            return;
        }
        // Open while the request still owns its account context. The descriptor pins these exact
        // bytes even if an unversioned key is overwritten before the worker gets CPU time.
        final InputStream bytes;
        try {
            bytes = source.get();
        } catch (RuntimeException error) {
            tag.accept("FAILED");
            return;
        }
        long generation = lifecycleGeneration;
        openStreams.add(bytes);
        try {
            scans.submit(() -> {
                String result = "FAILED";
                try (bytes) {
                    ContainerLifecycleManager.EndpointInfo target = ensureBackend(generation);
                    Future<String> scan = transports.submit(() -> scan(target.host(), target.port(), bytes,
                            settings.maxBytes(), settings.scanTimeoutSeconds()));
                    try {
                        result = scan.get(settings.scanTimeoutSeconds(), TimeUnit.SECONDS);
                    } finally {
                        scan.cancel(true);
                    }
                } catch (Exception error) {
                    LOG.warnv("GuardDuty scan backend unavailable: {0}", error.getClass().getSimpleName());
                } finally {
                    openStreams.remove(bytes);
                }
                tag.accept(result);
            });
        } catch (RuntimeException error) {
            openStreams.remove(bytes);
            try {
                bytes.close();
            } catch (IOException ignored) {
                // The failure status still has to be delivered if closing a rejected stream fails.
            }
            tag.accept("FAILED");
        }
    }

    private synchronized ContainerLifecycleManager.EndpointInfo ensureBackend(long generation) throws IOException {
        if (stopping || generation != lifecycleGeneration) {
            throw new IOException("Scanner is stopping");
        }
        if (endpoint != null && lifecycle.isContainerRunning(containerId)) {
            return endpoint;
        }
        String name = ContainerStorageHelper.dockerName(config, "guardduty-clamav");
        String volume = ContainerStorageHelper.resourceName(config, "guardduty", "clamav-db", "clamav-db");
        lifecycle.ensureVolume(volume);
        lifecycle.removeIfExistsStrict(name);
        ContainerBuilder.Builder spec = builder.newContainer(config.services().guardduty().malwareScan().image())
                .withName(name).withDockerNetwork(Optional.empty()).withLogRotation()
                .withNamedVolume(volume, "/var/lib/clamav")
                .withEnv("CLAMD_CONF_AlertExceedsMax", "yes")
                .withEnv("CLAMD_CONF_AlertEncrypted", "yes")
                .withEnv("CLAMD_CONF_FailIfCvdOlderThan", "7")
                .withEnv("CLAMD_CONF_StreamMaxLength", Long.toString(config.services().guardduty().malwareScan().maxBytes()));
        if (detector.isRunningInContainer()) {
            spec.withExposedPort(3310);
        } else {
            spec.withDynamicPort(3310);
        }
        containerId = lifecycle.createAndStart(spec.build()).containerId();
        ContainerLifecycleManager.EndpointInfo target = lifecycle.resolveEndpoint(containerId, 3310);
        long deadline = System.nanoTime() + Duration.ofSeconds(
                config.services().guardduty().malwareScan().startupTimeoutSeconds()).toNanos();
        while (!stopping && System.nanoTime() < deadline) {
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress(target.host(), target.port()), 1000);
                socket.setSoTimeout(1000);
                socket.getOutputStream().write("zPING\0".getBytes(StandardCharsets.US_ASCII));
                if (readReply(socket.getInputStream()).equals("PONG")) {
                    endpoint = target;
                    return target;
                }
            } catch (IOException ignored) {
                // clamd only starts serving after freshclam has installed a usable database.
            }
            try {
                Thread.sleep(500);
            } catch (InterruptedException error) {
                Thread.currentThread().interrupt();
                throw new IOException("Scanner startup interrupted", error);
            }
        }
        throw new IOException("Scanner startup timed out");
    }

    static String scan(String host, int port, InputStream source, long maxBytes, int timeoutSeconds)
            throws IOException {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), Math.multiplyExact(timeoutSeconds, 1000));
            socket.setSoTimeout(Math.multiplyExact(timeoutSeconds, 1000));
            DataOutputStream output = new DataOutputStream(socket.getOutputStream());
            output.write("zINSTREAM\0".getBytes(StandardCharsets.US_ASCII));
            byte[] chunk = new byte[65536];
            long total = 0;
            int count;
            while ((count = source.read(chunk)) != -1) {
                total += count;
                if (total > maxBytes) {
                    return "UNSUPPORTED";
                }
                output.writeInt(count);
                output.write(chunk, 0, count);
            }
            output.writeInt(0);
            output.flush();
            String reply = readReply(socket.getInputStream());
            if ("stream: OK".equals(reply)) {
                return "NO_THREATS_FOUND";
            }
            if (reply.startsWith("stream: Heuristics.Limits.Exceeded")
                    || reply.startsWith("stream: Heuristics.Encrypted")) {
                return "UNSUPPORTED";
            }
            if (reply.startsWith("stream: ") && reply.endsWith(" FOUND")) {
                return "THREATS_FOUND";
            }
            return "FAILED";
        }
    }

    private static String readReply(InputStream input) throws IOException {
        StringBuilder reply = new StringBuilder();
        for (int length = 0; length < 4096; length++) {
            int value = input.read();
            if (value == 0) {
                return reply.toString();
            }
            if (value < 0) {
                throw new IOException("Truncated clamd reply");
            }
            reply.append((char) value);
        }
        throw new IOException("Oversized clamd reply");
    }

    private static ExecutorService newScanExecutor() {
        return new ThreadPoolExecutor(2, 2, 0, TimeUnit.SECONDS,
                new ArrayBlockingQueue<>(64), Thread.ofVirtual().name("guardduty-scan-", 0).factory());
    }

    void onShutdown(@Observes @Priority(1000) ShutdownEvent ignored) {
        stop();
    }

    @Override
    public void stopManagedContainers() {
        stop();
    }

    @Override
    public void clear() {
        // The teardown phase closes resources before reset wipes the protection plans.
    }

    @Override
    public synchronized void afterReset() {
        if (stopping) {
            scans = newScanExecutor();
            transports = Executors.newVirtualThreadPerTaskExecutor();
            openStreams.clear();
            stopping = false;
        }
    }

    @PreDestroy
    void stop() {
        stopping = true;
        lifecycleGeneration++;
        scans.shutdownNow();
        transports.shutdownNow();
        for (InputStream stream : openStreams) {
            try {
                stream.close();
            } catch (IOException ignored) {
                // Continue releasing the other pending scans and the owned backend.
            }
        }
        synchronized (this) {
            if (containerId != null) {
                lifecycle.stopAndRemove(containerId, null);
                containerId = null;
                endpoint = null;
            }
        }
    }
}
