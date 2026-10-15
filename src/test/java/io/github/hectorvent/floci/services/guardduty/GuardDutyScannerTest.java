package io.github.hectorvent.floci.services.guardduty;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.docker.ContainerBuilder;
import io.github.hectorvent.floci.core.common.docker.ContainerDetector;
import io.github.hectorvent.floci.core.common.docker.ContainerLifecycleManager;
import io.github.hectorvent.floci.services.guardduty.model.MalwareProtectionPlan;
import io.quarkus.runtime.ShutdownEvent;
import jakarta.annotation.Priority;
import jakarta.enterprise.event.Observes;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.lang.reflect.Parameter;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class GuardDutyScannerTest {
    @Test
    void streamsEveryByteAndRecognisesCleanReply() throws Exception {
        assertEquals("NO_THREATS_FOUND", run("stream: OK\0"));
    }

    @Test
    void recognisesRealVirusReplyWithoutLoggingPayload() throws Exception {
        assertEquals("THREATS_FOUND", run("stream: Eicar-Signature FOUND\0"));
    }

    @Test
    void scannerErrorAndUnexpectedRepliesNeverCountAsClean() throws Exception {
        assertEquals("FAILED", run("stream: engine error ERROR\0"));
        assertEquals("FAILED", run("OK\0"));
        assertEquals("UNSUPPORTED", run("stream: Heuristics.Limits.Exceeded.MaxRecursion FOUND\0"));
        assertEquals("UNSUPPORTED", run("stream: Heuristics.Encrypted.Zip FOUND\0"));
    }

    @Test
    void disconnectIsAnError() {
        assertThrows(Exception.class, () -> run("stream: OK"));
    }

    @Test
    void actualClamdCleanAndEicar() throws Exception {
        String host = System.getenv("FLOCI_TEST_CLAMD_HOST");
        Assumptions.assumeTrue(host != null, "Requires the pinned real ClamAV sidecar");
        int port = Integer.parseInt(System.getenv().getOrDefault("FLOCI_TEST_CLAMD_PORT", "3310"));
        assertEquals("NO_THREATS_FOUND", GuardDutyScanner.scan(host, port,
                new ByteArrayInputStream("clinical XML".getBytes(StandardCharsets.UTF_8)), 1024, 30));
        String eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        assertEquals("THREATS_FOUND", GuardDutyScanner.scan(host, port,
                new ByteArrayInputStream(eicar.getBytes(StandardCharsets.US_ASCII)), 1024, 30));
    }

    @Test
    void shutdownWaitsForConcurrentCreationAndClosesQueuedStreams() throws Exception {
        EmulatorConfig config = mock(EmulatorConfig.class, RETURNS_DEEP_STUBS);
        when(config.services().guardduty().malwareScan().enabled()).thenReturn(true);
        when(config.services().guardduty().malwareScan().maxBytes()).thenReturn(1024L);
        when(config.services().guardduty().malwareScan().image()).thenReturn("test-image");
        when(config.docker().resourceNamespace()).thenReturn(Optional.of("scan-test"));
        GuardDutyService guardDuty = mock(GuardDutyService.class);
        MalwareProtectionPlan plan = new MalwareProtectionPlan();
        plan.setTaggingStatus("ENABLED");
        when(guardDuty.protectionForObject(anyString(), anyString(), anyString(), anyString()))
                .thenReturn(Optional.of(plan));
        ContainerBuilder builder = mock(ContainerBuilder.class, RETURNS_DEEP_STUBS);
        ContainerBuilder.Builder spec = mock(ContainerBuilder.Builder.class, org.mockito.Answers.RETURNS_SELF);
        when(builder.newContainer(anyString())).thenReturn(spec);
        ContainerLifecycleManager lifecycle = mock(ContainerLifecycleManager.class);
        CountDownLatch creating = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        when(lifecycle.createAndStart(any())).thenAnswer(call -> {
            creating.countDown();
            // Docker may finish a create call even after shutdown interrupts its worker.
            boolean waiting = true;
            while (waiting) {
                try {
                    release.await();
                    waiting = false;
                } catch (InterruptedException ignored) {
                    // Simulate an in-flight non-interruptible Docker request.
                }
            }
            return new ContainerLifecycleManager.ContainerInfo("owned-scanner", Map.of());
        });
        when(lifecycle.resolveEndpoint(anyString(), anyInt()))
                .thenReturn(new ContainerLifecycleManager.EndpointInfo("127.0.0.1", 1));
        GuardDutyScanner scanner = new GuardDutyScanner(config, guardDuty, builder, lifecycle,
                mock(ContainerDetector.class));
        List<AtomicBoolean> closed = new ArrayList<>();
        for (int index = 0; index < 5; index++) {
            AtomicBoolean flag = new AtomicBoolean();
            closed.add(flag);
            scanner.submit("000000000000", "eu-west-2", "bucket", "staging/file", 1,
                    () -> new ByteArrayInputStream(new byte[]{1}) {
                        @Override
                        public void close() {
                            flag.set(true);
                        }
                    }, ignored -> {});
        }
        assertTrue(creating.await(5, TimeUnit.SECONDS));
        CompletableFuture<Void> stopping = CompletableFuture.runAsync(scanner::stop);
        try {
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
            while (closed.stream().anyMatch(flag -> !flag.get()) && System.nanoTime() < deadline) {
                Thread.sleep(10);
            }
            assertTrue(closed.stream().allMatch(AtomicBoolean::get));
        } finally {
            release.countDown();
            stopping.get(5, TimeUnit.SECONDS);
        }
        verify(lifecycle).stopAndRemove("owned-scanner", null);
    }

    @Test
    void shutdownObserverRunsBeforeDefaultObservers() throws Exception {
        Parameter event = GuardDutyScanner.class
                .getDeclaredMethod("onShutdown", ShutdownEvent.class).getParameters()[0];
        assertTrue(event.isAnnotationPresent(Observes.class));
        assertTrue(event.getAnnotation(Priority.class).value() < jakarta.interceptor.Interceptor.Priority.APPLICATION + 500);
    }

    @Test
    void teardownIsIdempotentAndResetRestoresRealScanSubmission() throws Exception {
        EmulatorConfig config = mock(EmulatorConfig.class, RETURNS_DEEP_STUBS);
        when(config.services().guardduty().malwareScan().enabled()).thenReturn(true);
        when(config.services().guardduty().malwareScan().maxBytes()).thenReturn(1024L);
        when(config.services().guardduty().malwareScan().image()).thenReturn("test-image");
        GuardDutyService guardDuty = mock(GuardDutyService.class);
        MalwareProtectionPlan plan = new MalwareProtectionPlan();
        plan.setTaggingStatus("ENABLED");
        when(guardDuty.protectionForObject(anyString(), anyString(), anyString(), anyString()))
                .thenReturn(Optional.of(plan));
        ContainerBuilder builder = mock(ContainerBuilder.class);
        ContainerBuilder.Builder spec = mock(ContainerBuilder.Builder.class, org.mockito.Answers.RETURNS_SELF);
        when(builder.newContainer(anyString())).thenReturn(spec);
        ContainerLifecycleManager lifecycle = mock(ContainerLifecycleManager.class);
        when(lifecycle.createAndStart(any())).thenThrow(new IllegalStateException("backend unavailable"));
        GuardDutyScanner scanner = new GuardDutyScanner(config, guardDuty, builder, lifecycle,
                mock(ContainerDetector.class));
        LinkedBlockingQueue<String> results = new LinkedBlockingQueue<>();
        try {
            scanner.submit("000000000000", "eu-west-2", "bucket", "staging/file", 1,
                    () -> new ByteArrayInputStream(new byte[]{1}), results::add);
            assertEquals("FAILED", results.poll(5, TimeUnit.SECONDS));
            scanner.onShutdown(new ShutdownEvent());
            scanner.stopManagedContainers();
            scanner.stop();
            scanner.afterReset();
            scanner.submit("000000000000", "eu-west-2", "bucket", "staging/file", 1,
                    () -> new ByteArrayInputStream(new byte[]{1}), results::add);
            assertEquals("FAILED", results.poll(5, TimeUnit.SECONDS));
            verify(lifecycle, org.mockito.Mockito.times(2)).createAndStart(any());
        } finally {
            scanner.stop();
        }
    }

    private String run(String reply) throws Exception {
        try (ServerSocket listener = new ServerSocket(0)) {
            CompletableFuture<Void> server = CompletableFuture.runAsync(() -> {
                try (Socket connection = listener.accept()) {
                    DataInputStream input = new DataInputStream(connection.getInputStream());
                    assertEquals("zINSTREAM\0", new String(input.readNBytes(10), StandardCharsets.US_ASCII));
                    int count = input.readInt();
                    assertEquals("clinical bytes", new String(input.readNBytes(count), StandardCharsets.UTF_8));
                    assertEquals(0, input.readInt());
                    connection.getOutputStream().write(reply.getBytes(StandardCharsets.US_ASCII));
                } catch (Exception error) {
                    throw new RuntimeException(error);
                }
            });
            String result = GuardDutyScanner.scan("127.0.0.1", listener.getLocalPort(),
                    new ByteArrayInputStream("clinical bytes".getBytes(StandardCharsets.UTF_8)), 1024, 2);
            server.get();
            return result;
        }
    }
}
