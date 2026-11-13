package com.ulisesbocchio.jasyptspringboot.resolver;

import com.ulisesbocchio.jasyptspringboot.detector.DefaultPropertyDetector;
import com.ulisesbocchio.jasyptspringboot.exception.DecryptionException;
import org.jasypt.encryption.StringEncryptor;
import org.jasypt.exceptions.EncryptionOperationNotPossibleException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.env.PropertySource;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class DefaultPropertyResolverTest {

    private static final String CIPHERTEXT = "pCRvr+EmDC1DjSjRisfBpPOHWBEBLMiDtcO9KIhZeKOcfYkn2wdPz4TwdE1zlxTl";
    private static final String ENCRYPTED_VALUE = "ENC(" + CIPHERTEXT + ")";

    private StringEncryptor encryptor;
    private StandardEnvironment environment;
    private DefaultPropertyResolver resolver;

    @BeforeEach
    void setUp() {
        encryptor = mock(StringEncryptor.class);
        environment = new StandardEnvironment();
        resolver = new DefaultPropertyResolver(encryptor, new DefaultPropertyDetector(), environment);
    }

    private void givenDecryptionFails() {
        when(encryptor.decrypt(anyString())).thenThrow(new EncryptionOperationNotPossibleException());
    }

    @Test
    void failureMessageCarriesPropertyNameAndSourceWithoutLeakingSecrets() {
        givenDecryptionFails();
        PropertySource<?> source = new MapPropertySource("test-source", Collections.emptyMap());

        assertThatThrownBy(() -> resolver.resolvePropertyValue(ENCRYPTED_VALUE, "secret.property", source))
                .isInstanceOfSatisfying(DecryptionException.class, ex -> {
                    assertThat(ex.getMessage())
                            .contains("secret.property")
                            .contains("test-source")
                            .doesNotContain(CIPHERTEXT)
                            .doesNotContain(ENCRYPTED_VALUE)
                            .doesNotContain("ENC(");
                    assertThat(ex).hasCauseInstanceOf(EncryptionOperationNotPossibleException.class);
                });
    }

    @Test
    void failureMessageWithoutLocationDoesNotInventOne() {
        givenDecryptionFails();
        assertThatThrownBy(() -> resolver.resolvePropertyValue(ENCRYPTED_VALUE))
                .isInstanceOfSatisfying(DecryptionException.class, ex -> {
                    assertThat(ex.getMessage())
                            .startsWith("Unable to decrypt property.")
                            .doesNotContain(CIPHERTEXT)
                            .doesNotContain(ENCRYPTED_VALUE)
                            .doesNotContain("'null'")
                            .doesNotContain("source");
                    assertThat(ex).hasCauseInstanceOf(EncryptionOperationNotPossibleException.class);
                });
    }

    @Test
    void failureMessageWithNameButNoSourceOmitsSource() {
        givenDecryptionFails();
        assertThatThrownBy(() -> resolver.resolvePropertyValue(ENCRYPTED_VALUE, "secret.property", null))
                .isInstanceOf(DecryptionException.class)
                .hasMessageNotContaining(CIPHERTEXT)
                .hasMessageContaining("secret.property")
                .hasMessageNotContaining("source");
    }

    @Test
    void placeholderExpansionDoesNotLeakResolvedValueOnFailure() {
        givenDecryptionFails();
        environment.getPropertySources()
                .addFirst(new MapPropertySource("nested", Collections.singletonMap("cipher", CIPHERTEXT)));
        String placeholderValue = "ENC(${cipher})";

        assertThatThrownBy(() -> resolver.resolvePropertyValue(placeholderValue, "secret.property", null))
                .isInstanceOf(DecryptionException.class)
                .hasMessageNotContaining(CIPHERTEXT)
                .hasMessageNotContaining(placeholderValue)
                .hasMessageContaining("secret.property");
    }

    @Test
    void successfulDecryptionStillReturnsPlainValue() {
        when(encryptor.decrypt(CIPHERTEXT)).thenReturn("mypassword");

        assertThat(resolver.resolvePropertyValue(ENCRYPTED_VALUE, "secret.property", null))
                .isEqualTo("mypassword");
        assertThat(resolver.resolvePropertyValue(ENCRYPTED_VALUE)).isEqualTo("mypassword");
    }

    @Test
    void nonEncryptedValuesPassThroughUntouched() {
        assertThat(resolver.resolvePropertyValue("plain-value", "plain.property", null))
                .isEqualTo("plain-value");
        assertThat(resolver.resolvePropertyValue(null)).isNull();
    }

    @Test
    void nestedPlaceholderIsResolvedBeforeDecryption() {
        environment.getPropertySources()
                .addFirst(new MapPropertySource("nested", Collections.singletonMap("cipher", CIPHERTEXT)));
        when(encryptor.decrypt(anyString())).thenReturn("mypassword");

        assertThat(resolver.resolvePropertyValue("ENC(${cipher})")).isEqualTo("mypassword");
    }

    @Test
    void customResolverImplementationsRemainSourceCompatible() {
        com.ulisesbocchio.jasyptspringboot.EncryptablePropertyResolver custom = String::valueOf;

        assertThat(custom.resolvePropertyValue(ENCRYPTED_VALUE, "secret.property",
                new MapPropertySource("test-source", Collections.emptyMap())))
                .isEqualTo(ENCRYPTED_VALUE);
    }
}
