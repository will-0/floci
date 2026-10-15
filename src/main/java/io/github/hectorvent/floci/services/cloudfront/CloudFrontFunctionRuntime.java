package io.github.hectorvent.floci.services.cloudfront;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.services.cloudfront.model.CacheBehavior;
import io.github.hectorvent.floci.services.cloudfront.model.CloudFrontFunction;
import io.github.hectorvent.floci.services.cloudfront.model.DistributionConfig;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.graalvm.polyglot.Context;
import org.graalvm.polyglot.Value;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Executes published viewer-request JavaScript against the function's associated KVS snapshot. */
@ApplicationScoped
public class CloudFrontFunctionRuntime {
    @Inject CloudFrontService service;
    @Inject CloudFrontKeyValueService keyValues;
    @Inject ObjectMapper json;

    public record Result(Map<String, Object> value, String originId) {}

    public Result viewerRequest(DistributionConfig config, String normalized, Map<String, Object> request) {
        List<Map<String, String>> associations = config.getDefaultCacheBehavior() == null ? List.of()
                : config.getDefaultCacheBehavior().getFunctionAssociations();
        if (config.getCacheBehaviors() != null) {
            for (CacheBehavior behavior : config.getCacheBehaviors()) {
                if (CloudFrontRequestRouter.pathPatternMatches(behavior.getPathPattern(), normalized)) {
                    associations = behavior.getFunctionAssociations();
                    break;
                }
            }
        }
        if (associations == null) return new Result(request, null);
        for (Map<String, String> association : associations) {
            if (!"viewer-request".equals(association.get("EventType"))) continue;
            String arn = association.get("FunctionARN");
            String name = arn.substring(arn.lastIndexOf('/') + 1);
            return execute(service.describeFunction(name, "LIVE"), request);
        }
        return new Result(request, null);
    }

    @SuppressWarnings("unchecked")
    Result execute(CloudFrontFunction function, Map<String, Object> request) {
        try (Context context = Context.newBuilder("js").allowAllAccess(false)
                .option("engine.WarnInterpreterOnly", "false").build()) {
            Map<String, Object> snapshots = new LinkedHashMap<>();
            for (String arn : function.getKeyValueStoreArns()) {
                snapshots.put(arn, keyValues.get(arn).entries);
            }
            String code = function.getFunctionCode();
            // AWS management APIs carry a base64 blob; direct service callers can supply source.
            if (!code.contains("function") && !code.contains("=>")) {
                code = new String(Base64.getDecoder().decode(code), StandardCharsets.UTF_8);
            }
            context.eval("js", "globalThis.__stores=" + json.writeValueAsString(snapshots) + ";globalThis.__origin=null;" + """
                globalThis.__cloudfront = {
                  kvs: function(id) {
                    const stores = globalThis.__stores;
                    const keys = Object.keys(stores);
                    const key = id ? keys.find(k => k === id || k.endsWith('/' + id)) : keys[0];
                    const entries = stores[key] || {};
                    return {
                      get: async function(k, options) {
                        if (!Object.hasOwn(entries, k)) throw new Error('Key not found');
                        return options && options.format === 'json' ? JSON.parse(entries[k]) : entries[k];
                      },
                      exists: async function(k) { return Object.hasOwn(entries, k); },
                      meta: async function() { return {keyCount: Object.keys(entries).length}; }
                    };
                  },
                  selectRequestOriginById: function(id) { globalThis.__origin = id; }
                };
                """);
            code = code.replaceAll("import\\s+(\\w+)\\s+from\\s+['\"]cloudfront['\"];?", "const $1 = globalThis.__cloudfront;");
            context.eval("js", code);
            context.eval("js", "globalThis.__event={version:'1.0',context:{eventType:'viewer-request'},request:"
                    + json.writeValueAsString(request) + "};globalThis.__result=null;globalThis.__error=null;"
                    + "Promise.resolve(handler(globalThis.__event)).then(r=>globalThis.__result=r,e=>globalThis.__error=String(e));");
            Value bindings = context.getBindings("js");
            if (!bindings.getMember("__error").isNull()) throw new IllegalStateException(bindings.getMember("__error").asString());
            String result = context.eval("js", "JSON.stringify(globalThis.__result)").asString();
            if ("null".equals(result)) throw new IllegalStateException("Function did not complete synchronously");
            Value origin = bindings.getMember("__origin");
            return new Result(json.readValue(result, Map.class), origin.isNull() ? null : origin.asString());
        } catch (Exception e) {
            throw new IllegalStateException("CloudFront viewer-request function failed", e);
        }
    }
}
