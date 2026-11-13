package com.ulisesbocchio.jasyptspringboot.resolver;

import com.ulisesbocchio.jasyptspringboot.EncryptablePropertyDetector;
import com.ulisesbocchio.jasyptspringboot.EncryptablePropertyResolver;
import com.ulisesbocchio.jasyptspringboot.detector.DefaultPropertyDetector;
import com.ulisesbocchio.jasyptspringboot.exception.DecryptionException;
import org.jasypt.encryption.StringEncryptor;
import org.jasypt.exceptions.EncryptionOperationNotPossibleException;
import org.springframework.core.env.Environment;
import org.springframework.core.env.PropertySource;
import org.springframework.util.Assert;

import java.util.Optional;

/**
 * <p>DefaultPropertyResolver class.</p>
 *
 * @author Ulises Bocchio
 * @version $Id: $Id
 */
public class DefaultPropertyResolver implements EncryptablePropertyResolver {

    private final Environment environment;
    private StringEncryptor encryptor;
    private EncryptablePropertyDetector detector;

    /**
     * <p>Constructor for DefaultPropertyResolver.</p>
     *
     * @param encryptor a {@link org.jasypt.encryption.StringEncryptor} object
     * @param environment a {@link org.springframework.core.env.Environment} object
     */
    public DefaultPropertyResolver(StringEncryptor encryptor, Environment environment) {
        this(encryptor, new DefaultPropertyDetector(), environment);
    }

    /**
     * <p>Constructor for DefaultPropertyResolver.</p>
     *
     * @param encryptor a {@link org.jasypt.encryption.StringEncryptor} object
     * @param detector a {@link com.ulisesbocchio.jasyptspringboot.EncryptablePropertyDetector} object
     * @param environment a {@link org.springframework.core.env.Environment} object
     */
    public DefaultPropertyResolver(StringEncryptor encryptor, EncryptablePropertyDetector detector, Environment environment) {
        this.environment = environment;
        Assert.notNull(encryptor, "String encryptor can't be null");
        Assert.notNull(detector, "Encryptable Property detector can't be null");
        this.encryptor = encryptor;
        this.detector = detector;
    }

    /** {@inheritDoc} */
    @Override
    public String resolvePropertyValue(String value) {
        return resolvePropertyValue(value, null, null);
    }

    /** {@inheritDoc} */
    @Override
    public String resolvePropertyValue(String value, String name, PropertySource<?> source) {
        return Optional.ofNullable(value)
                .map(environment::resolvePlaceholders)
                .filter(detector::isEncrypted)
                .map(resolvedValue -> {
                    try {
                        String unwrappedProperty = detector.unwrapEncryptedValue(resolvedValue.trim());
                        String resolvedProperty = environment.resolvePlaceholders(unwrappedProperty);
                        return encryptor.decrypt(resolvedProperty);
                    } catch (EncryptionOperationNotPossibleException e) {
                        throw new DecryptionException(buildDecryptionFailureMessage(name, source), e);
                    }
                })
                .orElse(value);
    }

    private static String buildDecryptionFailureMessage(String name, PropertySource<?> source) {
        StringBuilder message = new StringBuilder("Unable to decrypt property");
        if (name != null) {
            message.append(" '").append(name).append("'");
        }
        if (source != null) {
            message.append(" from property source '").append(source.getName()).append("'");
        }
        message.append(". Decryption of Properties failed, make sure encryption/decryption passwords match");
        return message.toString();
    }
}
