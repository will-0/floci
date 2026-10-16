package io.github.hectorvent.floci.services.lambda.launcher;

import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.api.command.CopyArchiveFromContainerCmd;
import com.github.dockerjava.api.command.CopyArchiveToContainerCmd;
import com.github.dockerjava.api.exception.NotFoundException;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ContainerLauncherRuntimeCaCertTest {

    private static final String CA = "-----BEGIN CERTIFICATE-----\nFLOCI\n-----END CERTIFICATE-----\n";

    private final DockerClient docker = mock(DockerClient.class);
    private final AtomicReference<String> uploadedPath = new AtomicReference<>();
    private final AtomicReference<String> uploadedName = new AtomicReference<>();
    private final AtomicReference<String> uploaded = new AtomicReference<>();

    @BeforeEach
    void captureUpload() {
        CopyArchiveToContainerCmd upload = mock(CopyArchiveToContainerCmd.class);
        when(docker.copyArchiveToContainerCmd("c1")).thenReturn(upload);
        when(upload.withRemotePath(any())).thenAnswer(inv -> {
            uploadedPath.set(inv.getArgument(0));
            return upload;
        });
        when(upload.withTarInputStream(any())).thenAnswer(inv -> {
            try (TarArchiveInputStream tar = new TarArchiveInputStream(inv.<InputStream>getArgument(0))) {
                TarArchiveEntry entry = tar.getNextEntry();
                uploadedName.set(entry.getName());
                uploaded.set(new String(tar.readAllBytes(), StandardCharsets.UTF_8));
            }
            return upload;
        });
    }

    @Test
    void appendsTheCaAfterTheImagesCertificates() throws Exception {
        existing(regularFile("-----BEGIN CERTIFICATE-----\nRDS\n-----END CERTIFICATE-----"));

        ContainerLauncher.appendRuntimeCaCert(docker, "c1", CA, "fn");

        assertEquals("/", uploadedPath.get());
        assertEquals("var/runtime/ca-cert.pem", uploadedName.get());
        assertEquals("-----BEGIN CERTIFICATE-----\nRDS\n-----END CERTIFICATE-----\n" + CA, uploaded.get());
    }

    @Test
    void createsTheFileWhenTheImageHasNone() {
        CopyArchiveFromContainerCmd read = mock(CopyArchiveFromContainerCmd.class);
        when(docker.copyArchiveFromContainerCmd("c1", ContainerLauncher.RUNTIME_CA_CERT)).thenReturn(read);
        when(read.exec()).thenThrow(new NotFoundException("no such file"));

        ContainerLauncher.appendRuntimeCaCert(docker, "c1", CA, "fn");

        assertEquals(CA, uploaded.get());
    }

    @Test
    void leavesASymlinkAlone() throws Exception {
        TarArchiveEntry link = new TarArchiveEntry("ca-cert.pem", TarArchiveEntry.LF_SYMLINK);
        link.setLinkName("/etc/pki/tls/certs/ca-bundle.crt");
        existing(archive(link, new byte[0]));

        ContainerLauncher.appendRuntimeCaCert(docker, "c1", CA, "fn");

        assertNull(uploaded.get());
    }

    private void existing(byte[] tar) {
        CopyArchiveFromContainerCmd read = mock(CopyArchiveFromContainerCmd.class);
        when(docker.copyArchiveFromContainerCmd("c1", ContainerLauncher.RUNTIME_CA_CERT)).thenReturn(read);
        when(read.exec()).thenReturn(new ByteArrayInputStream(tar));
    }

    private static byte[] regularFile(String content) throws Exception {
        byte[] bytes = content.getBytes(StandardCharsets.UTF_8);
        TarArchiveEntry entry = new TarArchiveEntry("ca-cert.pem");
        entry.setSize(bytes.length);
        return archive(entry, bytes);
    }

    private static byte[] archive(TarArchiveEntry entry, byte[] content) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (TarArchiveOutputStream tar = new TarArchiveOutputStream(out)) {
            tar.putArchiveEntry(entry);
            tar.write(content);
            tar.closeArchiveEntry();
        }
        return out.toByteArray();
    }
}
