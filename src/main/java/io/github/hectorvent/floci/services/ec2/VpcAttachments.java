package io.github.hectorvent.floci.services.ec2;

import io.github.hectorvent.floci.services.ec2.model.NetworkInterface;
import io.github.hectorvent.floci.services.ec2.model.PrefixListEntry;
import io.github.hectorvent.floci.services.ec2.model.SecurityGroup;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

/**
 * Puts a service workload on a subnet behind its security groups and route table: an ENI in the
 * subnet, plus a protected network namespace the workload's containers join with
 * {@code --network container:<helperId>}. ECS tasks, VPC Lambda functions and RDS and
 * ElastiCache backends share it, so each enforces networking the same way.
 */
@ApplicationScoped
public class VpcAttachments {

    private final Ec2Service ec2Service;
    private final SecurityGroupFirewallManager firewallManager;

    @Inject
    public VpcAttachments(Ec2Service ec2Service, SecurityGroupFirewallManager firewallManager) {
        this.ec2Service = ec2Service;
        this.firewallManager = firewallManager;
    }

    public boolean enabled() {
        return firewallManager.enabled();
    }

    /**
     * Creates an ENI in {@code subnetId} (or adopts {@code existingEni}) and the namespace
     * around it. Requester-managed interfaces are the ones AWS creates for Lambda, RDS and
     * ElastiCache: they never hold a public address, so they reach out only through a NAT.
     */
    public Attachment attach(String service, String resourceId, String accountId, String region,
                             String subnetId, List<String> securityGroupIds, String description,
                             boolean requesterManaged, Optional<String> dockerNetwork,
                             Map<Integer, Integer> portBindings, Map<String, String> labels,
                             NetworkInterface existingEni) {
        NetworkInterface eni = existingEni;
        if (eni == null) {
            eni = ec2Service.createNetworkInterface(region, subnetId, description, null, List.of(),
                    securityGroupIds, List.of());
            ec2Service.holdNetworkInterfaceForService(region, eni.getNetworkInterfaceId(), requesterManaged);
        }
        String eniId = eni.getNetworkInterfaceId();
        SecurityGroupFirewallManager.Namespace namespace = null;
        try {
            namespace = firewallManager.createNamespace(service, resourceId, accountId, region,
                    dockerNetwork, portBindings, labels);
            List<String> groupIds = eni.getGroups().stream().map(g -> g.getGroupId()).toList();
            List<SecurityGroup> groups = ec2Service.describeSecurityGroups(region, groupIds, List.of(), Map.of());
            if (groups.size() != groupIds.size()) {
                throw new IllegalStateException("A security group of " + resourceId + " could not be resolved");
            }
            firewallManager.register(new SecurityGroupNftCompiler.Endpoint(accountId, region, eni.getVpcId(),
                    eniId, eni.getPrivateIpAddress(), namespace.transportAddress(), Set.copyOf(groupIds), groups),
                    namespace.helperId(), prefixLists(region, groups));
            return new Attachment(eni, namespace.helperId(), namespace.transportAddress());
        } catch (RuntimeException e) {
            if (namespace != null) {
                firewallManager.unregister(eniId);
                firewallManager.removeHelper(namespace.helperId());
            }
            release(region, eniId);
            throw e;
        }
    }

    /** Removes the namespace and the ENI. Safe to repeat. */
    public void detach(String region, String eniId) {
        firewallManager.unregister(eniId);
        release(region, eniId);
    }

    private void release(String region, String eniId) {
        try {
            ec2Service.releaseNetworkInterfaceFromService(region, eniId);
            ec2Service.deleteNetworkInterface(region, eniId);
        } catch (RuntimeException ignored) {
            // Already gone.
        }
    }

    private Map<String, List<String>> prefixLists(String region, List<SecurityGroup> groups) {
        Map<String, List<String>> prefixLists = new LinkedHashMap<>();
        groups.stream()
                .flatMap(group -> Stream.concat(group.getIpPermissions().stream(),
                        group.getIpPermissionsEgress().stream()))
                .flatMap(permission -> permission.getPrefixListIds().stream())
                .map(reference -> reference.getPrefixListId())
                .distinct()
                .forEach(id -> prefixLists.put(id, ec2Service.getManagedPrefixListEntries(region, id, null)
                        .stream().map(PrefixListEntry::getCidr).toList()));
        return prefixLists;
    }

    public record Attachment(NetworkInterface eni, String helperId, String transportAddress) {
        public String networkMode() {
            return "container:" + helperId;
        }
    }
}
