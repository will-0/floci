package io.github.hectorvent.floci.services.cloudfront;

import com.fasterxml.jackson.core.type.TypeReference;
import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.core.storage.StorageBackend;
import io.github.hectorvent.floci.core.storage.StorageFactory;
import io.github.hectorvent.floci.services.cloudfront.model.KeyValueStore;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

@ApplicationScoped
public class CloudFrontKeyValueService {
    private final StorageBackend<String, KeyValueStore> stores;
    private final RegionResolver regions;
    private final String account;

    @Inject
    public CloudFrontKeyValueService(StorageFactory factory, RegionResolver regions, EmulatorConfig config) {
        this.stores = factory.create("cloudfront", "cloudfront-key-value-stores.json",
                new TypeReference<Map<String, KeyValueStore>>() {});
        this.regions = regions;
        this.account = config.defaultAccountId();
    }

    public synchronized KeyValueStore create(String name, String comment) {
        if (name == null || name.isBlank()) {
            throw new AwsException("InvalidArgument", "Name is required", 400);
        }
        if (stores.get(name).isPresent()) {
            throw new AwsException("EntityAlreadyExists", "Key value store already exists", 409);
        }
        KeyValueStore store = new KeyValueStore();
        store.id = UUID.randomUUID().toString();
        store.name = name;
        store.comment = comment;
        store.arn = regions.buildGlobalArn("cloudfront", account, "key-value-store/" + store.id);
        touch(store);
        return store;
    }

    public KeyValueStore get(String nameOrArn) {
        return stores.scan(k -> true).stream()
                .filter(s -> s.name.equals(nameOrArn) || s.arn.equals(nameOrArn) || s.id.equals(nameOrArn))
                .findFirst().orElseThrow(() -> new AwsException("ResourceNotFoundException", "Key value store not found", 404));
    }

    public List<KeyValueStore> list() { return stores.scan(k -> true); }

    public synchronized KeyValueStore update(String name, String etag, String comment) {
        KeyValueStore store = get(name);
        match(store, etag);
        store.comment = comment;
        touch(store);
        return store;
    }

    public synchronized void delete(String name, String etag) {
        KeyValueStore store = get(name);
        match(store, etag);
        stores.delete(store.name);
    }

    public synchronized KeyValueStore write(String arn, String etag, Map<String, String> puts, List<String> deletes) {
        KeyValueStore store = get(arn);
        if (!Objects.equals(store.etag, etag)) {
            throw new AwsException("ConflictException", "The If-Match ETag does not match", 409);
        }
        store.entries.putAll(puts);
        deletes.forEach(store.entries::remove);
        touch(store);
        return store;
    }

    private void match(KeyValueStore store, String etag) {
        if (!Objects.equals(store.etag, etag)) {
            throw new AwsException("PreconditionFailed", "The If-Match ETag does not match", 412);
        }
    }

    private void touch(KeyValueStore store) {
        store.etag = UUID.randomUUID().toString();
        store.modified = Instant.now();
        stores.put(store.name, store);
    }
}
