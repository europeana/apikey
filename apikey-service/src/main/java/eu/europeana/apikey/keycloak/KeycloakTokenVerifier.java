package eu.europeana.apikey.keycloak;

import org.keycloak.TokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.representations.AccessToken;
import org.springframework.beans.factory.BeanInitializationException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Class used for verifiying token signature. It uses the realm public key from properties.
 *
 */
@Component
public class KeycloakTokenVerifier {
    @Value("${keycloak.realm-public-key}")
    private String realmPublicKey;

    /** Public key of the realm that is used to verify the token signature */
    private static PublicKey publicKey;

    @PostConstruct
    public void init() {
        toPublicKey();
    }

    /**
     * Convert base64 realm public key to PublicKey object that can be used for signature verification.
     */
    private void toPublicKey() {
        try {
            byte[] publicBytes = Base64.getDecoder().decode(realmPublicKey);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            publicKey = keyFactory.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new BeanInitializationException("Public key could not be prepared", e);
        }
    }

    /**
     * Return the realm public key
     * @return public key of the realm
     */
    public PublicKey getPublicKey() {
        return publicKey;
    }

    /**
     * Verify JWT token with the realm public key. Return an AccessToken that can be used to authorize further requests.
     * @param token base64 encoded JWT token
     * @return access token object
     * @throws VerificationException
     */
    static AccessToken verifyToken(String token) throws VerificationException {
        TokenVerifier<AccessToken> verifier = TokenVerifier.create(token, AccessToken.class);
        return verifier.publicKey(publicKey).verify().getToken();
    }
}
