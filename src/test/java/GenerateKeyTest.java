import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;


import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.SignatureException;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;


class GenerateKeyTest {
    private GenerateKey generateKey;

    @BeforeEach
    public void setup()
            throws InvalidKeySpecException, NoSuchAlgorithmException {
        generateKey = new GenerateKey(SignatureAlgorithm.RS256);
        generateKey.generate();
    }

    @Test
    void givenTokenSignedWithPrivateKey_whenVerifyWithPublicKey_thenNoException() {

        Map<String, Object> claims = new HashMap<>();
        claims.put("Claim1", "Value1");
        Date expiry = Date.from(LocalDateTime.now().plusMinutes(2).toInstant(ZoneOffset.UTC));
        String jwt = Jwts.builder().setClaims(claims).setSubject("asubject").setExpiration(expiry).signWith(generateKey.getPrivateKey()).compact();

        assertDoesNotThrow(() -> {
            Jwts.parserBuilder().setSigningKey(generateKey.getPublicKey()).build().parseClaimsJws(jwt);
        });
    }

    @Test
    void givenTokenSignedWithPrivateKey_whenVerifyWithDifferentPublicKey_thenThrowSignatureException()
            throws InvalidKeySpecException, NoSuchAlgorithmException {

        Map<String, Object> claims = new HashMap<>();
        claims.put("Claim1", "Value1");
        Date expiry = Date.from(LocalDateTime.now().plusMinutes(2).toInstant(ZoneOffset.UTC));
        String jwt = Jwts.builder().setClaims(claims).setSubject("asubject").setExpiration(expiry).signWith(generateKey.getPrivateKey()).compact();

        generateKey.generate();

        assertThrows(SignatureException.class, () -> Jwts.parserBuilder().setSigningKey(generateKey.getPublicKey()).build().parseClaimsJws(jwt));
    }
}
