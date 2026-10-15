package io.github.hectorvent.floci.services.cloudfront;

import io.github.hectorvent.floci.services.cloudfront.model.CloudFrontFunction;
import io.github.hectorvent.floci.services.cloudfront.model.KeyValueStore;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

@QuarkusTest
class CloudFrontFunctionRuntimeTest {
    @Inject CloudFrontFunctionRuntime runtime;
    @Inject CloudFrontKeyValueService stores;

    @Test
    void executesPublishedSourceWithAssociatedKvsAndAsyncUriRewrite() {
        KeyValueStore store = stores.create("function-" + UUID.randomUUID(), "test");
        stores.write(store.arn, store.etag, Map.of("releases", "[{\"v\":\"abcdef123456\"}]"), List.of());
        CloudFrontFunction function = new CloudFrontFunction();
        function.setKeyValueStoreArns(List.of(store.arn));
        String source = """
            import cf from 'cloudfront';
            const kvs = cf.kvs();
            async function handler(event) {
                const raw = await kvs.get('releases');
                const release = JSON.parse(raw)[0].v;
                event.request.uri = '/' + release + '/index.html';
                return event.request;
            }
            """;
        function.setFunctionCode(Base64.getEncoder().encodeToString(source.getBytes(StandardCharsets.UTF_8)));
        CloudFrontFunctionRuntime.Result result = runtime.execute(function, Map.of("uri", "/requests", "headers", Map.of()));
        assertEquals("/abcdef123456/index.html", result.value().get("uri"));
    }

    @Test
    void supportsGeneratedResponsesAndExplicitOriginSelection() {
        CloudFrontFunction function = new CloudFrontFunction();
        function.setFunctionCode("import cf from 'cloudfront'; function handler(e) { cf.selectRequestOriginById('legacy'); return {statusCode:302,headers:{location:{value:'/target'}}}; }");
        CloudFrontFunctionRuntime.Result result = runtime.execute(function, Map.of("uri", "/"));
        assertEquals("legacy", result.originId());
        assertEquals(302, result.value().get("statusCode"));
    }
}
