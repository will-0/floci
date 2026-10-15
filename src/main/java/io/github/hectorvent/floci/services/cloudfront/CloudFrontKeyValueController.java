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
import java.util.function.Supplier;

@Path("/2020-05-31/key-value-store")
public class CloudFrontKeyValueController {
    @Inject CloudFrontKeyValueService service;

    @POST @Path("")
    public Response create(String body) {
        return control(() -> xml(service.create(XmlParser.extractFirst(body, "Name", null),
                XmlParser.extractFirst(body, "Comment", null)), 201));
    }
    @GET @Path("{name}")
    public Response describe(@PathParam("name") String name) { return control(() -> xml(service.get(name), 200)); }

    @PUT @Path("{name}")
    public Response update(@PathParam("name") String name, @HeaderParam("If-Match") String etag, String body) {
        return control(() -> xml(service.update(name, etag, XmlParser.extractFirst(body, "Comment", null)), 200));
    }
    @DELETE @Path("{name}")
    public Response delete(@PathParam("name") String name, @HeaderParam("If-Match") String etag) {
        return control(() -> {
            service.delete(name, etag);
            return Response.noContent().build();
        });
    }
    @GET @Path("")
    public Response list() {
        XmlBuilder xml = new XmlBuilder().start("KeyValueStoreList", AwsNamespaces.CLOUDFRONT)
                .elem("Quantity", service.list().size()).elem("MaxItems", 100).elem("IsTruncated", false).start("Items");
        service.list().forEach(s -> append(xml.start("KeyValueStoreSummary"), s).end("KeyValueStoreSummary"));
        return Response.ok(xml.end("Items").end("KeyValueStoreList").build(), "application/xml").build();
    }

    private Response control(Supplier<Response> action) {
        try {
            return action.get();
        } catch (AwsException e) {
            String code = "ResourceNotFoundException".equals(e.getErrorCode()) ? "EntityNotFound" : e.getErrorCode();
            String body = new XmlBuilder().start("ErrorResponse", AwsNamespaces.CLOUDFRONT).start("Error")
                    .elem("Type", "Client").elem("Code", code).elem("Message", e.getMessage())
                    .end("Error").end("ErrorResponse").build();
            return Response.status(e.getHttpStatus()).type("application/xml").entity(body).build();
        }
    }

    private XmlBuilder append(XmlBuilder x, KeyValueStore s) {
        return x.elem("Name", s.name).elem("Id", s.id).elem("ARN", s.arn).elem("Comment", s.comment)
                .elem("Status", "READY").elem("LastModifiedTime", s.modified.toString());
    }
    private Response xml(KeyValueStore s, int status) {
        return Response.status(status).type("application/xml").header("ETag", s.etag)
                .entity(append(new XmlBuilder().start("KeyValueStore", AwsNamespaces.CLOUDFRONT), s).end("KeyValueStore").build()).build();
    }
}
