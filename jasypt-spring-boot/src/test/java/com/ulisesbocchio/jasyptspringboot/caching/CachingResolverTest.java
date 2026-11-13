package com.ulisesbocchio.jasyptspringboot.caching;

import com.ulisesbocchio.jasyptspringboot.EncryptablePropertyFilter;
import com.ulisesbocchio.jasyptspringboot.EncryptablePropertyResolver;
import com.ulisesbocchio.jasyptspringboot.exception.DecryptionException;
import com.ulisesbocchio.jasyptspringboot.filter.DefaultPropertyFilter;
import org.junit.jupiter.api.Test;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.PropertySource;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CachingResolverTest {

    private final EncryptablePropertyFilter filter = new DefaultPropertyFilter(null, null, null, null);

    @Test
    void propertyNameAndSourceArePassedToResolverOnFailure() {
        PropertySource<Map<String, Object>> source =
                new MapPropertySource("failing-source", Map.of("secret.property", "ENC(ciphertext)"));
        EncryptablePropertyResolver resolver = new LocationAwareResolver();
        CachingResolver cachingResolver = new CachingResolver(resolver, filter, source);

        assertThatThrownBy(() -> cachingResolver.resolveProperty("secret.property"))
                .isInstanceOf(DecryptionException.class)
                .hasMessageContaining("secret.property")
                .hasMessageContaining("failing-source")
                .hasMessageNotContaining("ciphertext");
    }

    @Test
    void resolvedValueIsCachedUntilRefresh() {
        Map<String, Object> values = new HashMap<>();
        values.put("secret.property", "ENC(ciphertext)");
        MapPropertySource source = new MapPropertySource("test-source", values);
        LocationAwareResolver resolver = new LocationAwareResolver();
        CachingResolver cachingResolver = new CachingResolver(resolver, filter, source);

        assertThat(cachingResolver.resolveProperty("secret.property")).isEqualTo("decrypted");
        assertThat(cachingResolver.resolveProperty("secret.property")).isEqualTo("decrypted");
        assertThat(resolver.invocations).isEqualTo(1);

        cachingResolver.refresh();
        assertThat(cachingResolver.resolveProperty("secret.property")).isEqualTo("decrypted");
        assertThat(resolver.invocations).isEqualTo(2);
    }

    private static class LocationAwareResolver implements EncryptablePropertyResolver {
        private int invocations;

        @Override
        public String resolvePropertyValue(String value, String name, PropertySource<?> source) {
            invocations++;
            if (value.startsWith("ENC(")) {
                if ("secret.property".equals(name) && "failing-source".equals(source.getName())) {
                    throw new DecryptionException(
                            "Unable to decrypt property '" + name + "' from property source '" + source.getName() + "'");
                }
                return "decrypted";
            }
            return value;
        }

        @Override
        public String resolvePropertyValue(String value) {
            if (value.startsWith("ENC(")) {
                return "decrypted";
            }
            return value;
        }
    }
}
