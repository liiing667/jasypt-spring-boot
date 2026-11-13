package com.ulisesbocchio.jasyptspringboot;

import org.springframework.core.env.PropertySource;

/**
 * An interface to resolve property values that may be encrypted.
 *
 * @author Ulises Bocchio
 * @version $Id: $Id
 */
public interface EncryptablePropertyResolver {

    /**
     * Returns the unencrypted version of the value provided free on any prefixes/suffixes or any other metadata
     * surrounding the encrypted value. Or the actual same String if no encryption was detected.
     *
     * @param value the property value
     * @return either the same value if the value is not encrypted, or the decrypted version.
     */
    String resolvePropertyValue(String value);

    /**
     * Same contract as {@link #resolvePropertyValue(String)}, but receives the property name and the
     * {@link PropertySource} the value originates from so that failure diagnostics can carry location
     * information without exposing encrypted (or resolved) values.
     *
     * @param value  the property value
     * @param name   the property name, or {@code null} when not available
     * @param source the property source the value originates from, or {@code null} when not available
     * @return either the same value if the value is not encrypted, or the decrypted version.
     */
    default String resolvePropertyValue(String value, String name, PropertySource<?> source) {
        return resolvePropertyValue(value);
    }
}
