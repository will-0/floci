package io.github.hectorvent.floci.services.cloudfront;

import io.github.hectorvent.floci.services.elbv2.ElbV2DataPlane;
import io.github.hectorvent.floci.services.route53.Route53Service;
import org.junit.jupiter.api.Test;

import java.net.URI;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class CloudFrontNativeOriginResolverTest {
    @Test
    void resolvesOwnedAliasesOnlyAndNeverTrustsArbitraryPrivateHosts() {
        CloudFrontNativeOriginResolver resolver = new CloudFrontNativeOriginResolver();
        resolver.dataPlane = mock(ElbV2DataPlane.class);
        resolver.route53 = mock(Route53Service.class);
        when(resolver.route53.findAliasTarget("000000000000", "origin.example.test"))
                .thenReturn("native.elb.localhost.floci.io.");
        when(resolver.dataPlane.isNativeOrigin("native.elb.localhost.floci.io", "origin.example.test", 443,
                "000000000000")).thenReturn(true);
        assertTrue(resolver.isNativeOrigin(URI.create("https://origin.example.test/path"), "origin.example.test", "000000000000"));
        assertFalse(resolver.isNativeOrigin(URI.create("https://127.0.0.1/path"), "127.0.0.1", "000000000000"));
        assertFalse(resolver.isNativeOrigin(URI.create("https://origin.example.test:444/path"), "origin.example.test", "000000000000"));
        assertFalse(resolver.isNativeOrigin(URI.create("https://origin.example.test/path"), "origin.example.test", "111111111111"));
    }
}
