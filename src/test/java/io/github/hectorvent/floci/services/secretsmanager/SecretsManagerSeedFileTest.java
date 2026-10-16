package io.github.hectorvent.floci.services.secretsmanager;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.core.storage.InMemoryStorage;
import io.github.hectorvent.floci.services.secretsmanager.model.Secret;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class SecretsManagerSeedFileTest {

    private static final String REGION = "us-east-1";

    @TempDir
    Path tempDir;

    private Path seedFile;
    private SecretsManagerService service;

    @BeforeEach
    void setUp() throws Exception {
        seedFile = tempDir.resolve("seed.json");
        Files.writeString(seedFile, """
                {"app/token": "plain-value", "app/db": {"username": "admin", "port": 5432}}
                """);
        service = new SecretsManagerService(new InMemoryStorage<String, Secret>(), 30,
                new RegionResolver(REGION, "000000000000"), null, new ObjectMapper(), null,
                seedFile.toString());
    }

    @Test
    void seededStringIsUsedVerbatim() {
        Secret secret = service.createSecret("app/token", null, null, null, null, null, REGION);

        assertNotNull(secret.getCurrentVersionId());
        assertEquals("plain-value", service.getSecretValue("app/token", null, "AWSCURRENT", REGION).getSecretString());
    }

    @Test
    void seededObjectBecomesCompactJson() {
        service.createSecret("app/db", null, null, null, null, null, REGION);

        assertEquals("{\"username\":\"admin\",\"port\":5432}",
                service.getSecretValue("app/db", null, null, REGION).getSecretString());
    }

    @Test
    void explicitValueWinsOverSeed() {
        service.createSecret("app/token", "explicit", null, null, null, null, REGION);

        assertEquals("explicit", service.getSecretValue("app/token", null, null, REGION).getSecretString());
    }

    @Test
    void unlistedNameStaysEmpty() {
        Secret secret = service.createSecret("app/other", null, null, null, null, null, REGION);

        assertNull(secret.getCurrentVersionId());
        assertTrue(secret.getVersions().isEmpty());
    }

    @Test
    void seedFileIsReadAtCreateTime() throws Exception {
        Files.writeString(seedFile, "{\"app/late\": \"added-later\"}");

        service.createSecret("app/late", null, null, null, null, null, REGION);

        assertEquals("added-later", service.getSecretValue("app/late", null, null, REGION).getSecretString());
    }

    @Test
    void malformedSeedFileFailsTheCreate() throws Exception {
        Files.writeString(seedFile, "[\"not\", \"an object\"]");

        AwsException error = assertThrows(AwsException.class,
                () -> service.createSecret("app/token", null, null, null, null, null, REGION));
        assertEquals("InternalServiceError", error.getErrorCode());
    }

    @Test
    void missingSeedFileChangesNothing() throws Exception {
        Files.delete(seedFile);

        Secret secret = service.createSecret("app/token", null, null, null, null, null, REGION);

        assertNull(secret.getCurrentVersionId());
    }
}
