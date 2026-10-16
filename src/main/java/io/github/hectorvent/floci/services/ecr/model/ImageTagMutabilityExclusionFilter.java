package io.github.hectorvent.floci.services.ecr.model;

import io.quarkus.runtime.annotations.RegisterForReflection;

import java.util.regex.Pattern;

/**
 * A tag pattern that inverts a repository's tag mutability: under
 * {@code IMMUTABLE_WITH_EXCLUSION} matching tags stay mutable, under {@code MUTABLE_WITH_EXCLUSION}
 * matching tags become immutable. {@code WILDCARD} is the only filter type, where {@code *}
 * matches any run of characters and the pattern must cover the whole tag.
 *
 * @see <a href="https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_ImageTagMutabilityExclusionFilter.html">AWS ECR ImageTagMutabilityExclusionFilter</a>
 */
@RegisterForReflection
public class ImageTagMutabilityExclusionFilter {
    private String filterType;
    private String filter;

    public ImageTagMutabilityExclusionFilter() {}

    public ImageTagMutabilityExclusionFilter(String filterType, String filter) {
        this.filterType = filterType;
        this.filter = filter;
    }

    public String getFilterType() { return filterType; }
    public void setFilterType(String filterType) { this.filterType = filterType; }

    public String getFilter() { return filter; }
    public void setFilter(String filter) { this.filter = filter; }

    public boolean matches(String tag) {
        if (tag == null || filter == null) {
            return false;
        }
        StringBuilder regex = new StringBuilder();
        for (String literal : filter.split("\\*", -1)) {
            if (!regex.isEmpty()) {
                regex.append(".*");
            }
            regex.append(Pattern.quote(literal));
        }
        return Pattern.matches(regex.toString(), tag);
    }
}
