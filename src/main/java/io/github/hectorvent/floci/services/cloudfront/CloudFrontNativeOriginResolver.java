package io.github.hectorvent.floci.services.cloudfront;

import io.github.hectorvent.floci.services.elbv2.ElbV2DataPlane;
import io.github.hectorvent.floci.services.route53.Route53Service;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.net.URI;
import java.util.HashSet;
import java.util.Set;

@ApplicationScoped
public class CloudFrontNativeOriginResolver {
    @Inject ElbV2DataPlane dataPlane;
    @Inject Route53Service route53;

    boolean isNativeOrigin(URI target, String requestHost, String accountId) {
        int port = target.getPort() >= 0 ? target.getPort() : "https".equals(target.getScheme()) ? 443 : 80;
        String host = normalize(target.getHost());
        Set<String> visited = new HashSet<>();
        while (visited.add(host) && visited.size() <= 8) {
            if (dataPlane.isNativeOrigin(host, requestHost, port, accountId)) {
                return true;
            }
            String alias = route53.findAliasTarget(accountId, host);
            if (alias == null) {
                return false;
            }
            host = normalize(alias);
        }
        return false;
    }

    private static String normalize(String host) {
        return CloudFrontServingController.normalizeHost(host).replaceFirst("\\.$", "");
    }
}
