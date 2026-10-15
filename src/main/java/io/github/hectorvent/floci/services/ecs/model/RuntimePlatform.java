package io.github.hectorvent.floci.services.ecs.model;

import io.quarkus.runtime.annotations.RegisterForReflection;

/**
 * The {@code runtimePlatform} of an ECS task definition:
 * {@code {"cpuArchitecture": "X86_64"|"ARM64", "operatingSystemFamily": "LINUX"|"WINDOWS_SERVER_*"}}.
 *
 * <p>Modelled for RegisterTaskDefinition/DescribeTaskDefinition round-trip fidelity — a client that
 * reads back what it registered (Terraform, or a deploy tool verifying its own write) must see the
 * platform it asked for. Container image pulls and creation use this declared platform; running
 * a different architecture requires the Docker daemon to support it.
 */
@RegisterForReflection
public record RuntimePlatform(String cpuArchitecture, String operatingSystemFamily) {
}
