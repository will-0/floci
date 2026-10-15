package io.github.hectorvent.floci.services.cloudfront;

import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.common.AwsNamespaces;
import io.github.hectorvent.floci.core.common.XmlBuilder;
import io.github.hectorvent.floci.core.common.XmlParser;
import io.github.hectorvent.floci.services.cloudfront.model.KeyValueStore;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.Response;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Path("/key-value-stores")
public class CloudFrontKeyValueDataController {
    @Inject CloudFrontKeyValueService service;

    @GET @Path("{arn}") @Produces("application/json")
    public Response dataDescribe(@PathParam("arn") String arn) {
        KeyValueStore store = service.get(arn);
        return json(store, Map.of("KvsARN", store.arn, "ItemCount", store.entries.size(), "TotalSizeInBytes", size(store),
                "Created", store.created.toEpochMilli() / 1000.0, "LastModified", store.modified.toEpochMilli() / 1000.0, "Status", "READY"));
    }
    @GET @Path("{arn}/keys/{key}") @Produces("application/json")
    public Response getKey(@PathParam("arn") String arn, @PathParam("key") String key) {
        KeyValueStore store = service.get(arn);
        if (!store.entries.containsKey(key)) throw new AwsException("ResourceNotFoundException", "Key not found", 404);
        return json(store, Map.of("Key", key, "Value", store.entries.get(key), "ItemCount", store.entries.size(), "TotalSizeInBytes", size(store)));
    }
    @PUT @Path("{arn}/keys/{key}") @Consumes("application/json") @Produces("application/json")
    public Response putKey(@PathParam("arn") String arn, @PathParam("key") String key,
                           @HeaderParam("If-Match") String etag, Map<String, Object> body) {
        return stats(service.write(arn, etag, Map.of(key, body.get("Value").toString()), List.of()));
    }
    @DELETE @Path("{arn}/keys/{key}") @Produces("application/json")
    public Response deleteKey(@PathParam("arn") String arn, @PathParam("key") String key, @HeaderParam("If-Match") String etag) {
        return stats(service.write(arn, etag, Map.of(), List.of(key)));
    }
    @POST @Path("{arn}/keys") @Consumes("application/json") @Produces("application/json")
    public Response updateKeys(@PathParam("arn") String arn, @HeaderParam("If-Match") String etag, Map<String, Object> body) {
        Map<String, String> puts = new LinkedHashMap<>();
        for (Object raw : (List<?>) body.getOrDefault("Puts", List.of())) {
            Map<?, ?> item = (Map<?, ?>) raw;
            puts.put(item.get("Key").toString(), item.get("Value").toString());
        }
        List<String> deletes = ((List<?>) body.getOrDefault("Deletes", List.of())).stream()
                .map(raw -> ((Map<?, ?>) raw).get("Key").toString()).toList();
        return stats(service.write(arn, etag, puts, deletes));
    }
    @GET @Path("{arn}/keys") @Produces("application/json")
    public Response listKeys(@PathParam("arn") String arn) {
        KeyValueStore store = service.get(arn);
        return json(store, Map.of("Items", store.entries.entrySet().stream().map(e -> Map.of("Key", e.getKey(), "Value", e.getValue())).toList()));
    }

    private Response stats(KeyValueStore s) { return json(s, Map.of("ItemCount", s.entries.size(), "TotalSizeInBytes", size(s))); }
    private Response json(KeyValueStore s, Object body) { return Response.ok(body).header("ETag", s.etag).build(); }
    private long size(KeyValueStore s) { return s.entries.entrySet().stream().mapToLong(e -> (e.getKey() + e.getValue()).getBytes(StandardCharsets.UTF_8).length).sum(); }
}
