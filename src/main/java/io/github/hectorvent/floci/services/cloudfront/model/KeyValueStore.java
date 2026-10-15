package io.github.hectorvent.floci.services.cloudfront.model;

import io.quarkus.runtime.annotations.RegisterForReflection;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

@RegisterForReflection
public class KeyValueStore {
    public String id;
    public String name;
    public String arn;
    public String comment;
    public String etag;
    public Instant created = Instant.now();
    public Instant modified = created;
    public Map<String, String> entries = new LinkedHashMap<>();
}
