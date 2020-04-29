import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.SignatureException;

public class GenerateKeyTest
{
    private GenerateKey generateKey;
    @Before
    public void setup()
        throws InvalidKeySpecException, NoSuchAlgorithmException
    {
        generateKey = new GenerateKey( SignatureAlgorithm.RS256 );
        generateKey.generate();
    }

    @Test
    public void givenTokenSignedWithPrivateKey_whenVerifyWithPublicKey_thenNoException() {

        Map<String, Object> claims = new HashMap<>();
        claims.put( "Claim1", "Value1" );
        Date expiry = Date.from( LocalDateTime.now().plusMinutes( 2 ).toInstant( ZoneOffset.UTC ) );
        String jwt = Jwts.builder().setClaims( claims ).setSubject( "asubject" ).setExpiration( expiry ).signWith( generateKey.getPrivateKey() ).compact();

        Jwts.parserBuilder().setSigningKey( generateKey.getPublicKey() ).build().parseClaimsJws( jwt );
    }

    @Test(expected = SignatureException.class )
    public void givenTokenSignedWithPrivateKey_whenVerifyWithDifferentPublicKey_thenThrowSignatureException()
        throws InvalidKeySpecException, NoSuchAlgorithmException
    {

        Map<String, Object> claims = new HashMap<>();
        claims.put( "Claim1", "Value1" );
        Date expiry = Date.from( LocalDateTime.now().plusMinutes( 2 ).toInstant( ZoneOffset.UTC ) );
        String jwt = Jwts.builder().setClaims( claims ).setSubject( "asubject" ).setExpiration( expiry ).signWith( generateKey.getPrivateKey() ).compact();

        generateKey.generate();
        Jwts.parserBuilder().setSigningKey( generateKey.getPublicKey() ).build().parseClaimsJws( jwt );
    }
}
