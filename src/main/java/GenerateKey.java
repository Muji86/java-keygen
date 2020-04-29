import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

public class GenerateKey
{
    private final SignatureAlgorithm signatureAlgorithm;
    private PublicKey publicKey;
    private PrivateKey privateKey;
    private String publicKeyString;
    private String privateKeyString;

    public GenerateKey( SignatureAlgorithm signatureAlgorithm )
    {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    public void generate()
        throws InvalidKeySpecException, NoSuchAlgorithmException
    {
        KeyPair keyPair = Keys.keyPairFor( signatureAlgorithm );

        privateKeyString = getPrivateKeyString( keyPair );
        publicKeyString = getPublicKeyString( keyPair );

        privateKey = getPrivateKey( privateKeyString );
        publicKey = getPublicKey( publicKeyString );

        test();
    }

    public String getPublicKeyString() {
        return this.publicKeyString;
    }

    public String getPrivateKeyString() {
        return this.privateKeyString;
    }

    public static void main( String[] args )
        throws InvalidKeySpecException, NoSuchAlgorithmException
    {
        GenerateKey generateKey = new GenerateKey(SignatureAlgorithm.RS256);
        generateKey.generate();
    }


    private String getPublicKeyString(KeyPair keyPair) {
        byte[] encodedPublic = keyPair.getPublic().getEncoded();
        return Base64.getEncoder().encodeToString( encodedPublic );
    }

    private String getPrivateKeyString(KeyPair keyPair) {
        byte[] encodedPrivate = keyPair.getPrivate().getEncoded();
        return Base64.getEncoder().encodeToString( encodedPrivate );
    }

    public void test()
    {
        Map<String, Object> claims = new HashMap<>();
        claims.put( "Claim1", "Value1" );
        Date expiry = Date.from( LocalDateTime.now().plusMinutes( 2 ).toInstant( ZoneOffset.UTC ) );
        String jwt = Jwts.builder().setClaims( claims ).setSubject( "asubject" ).setExpiration( expiry ).signWith( privateKey ).compact();

        Jwts.parserBuilder().setSigningKey( publicKey ).build().parseClaimsJws( jwt );
    }

    public PrivateKey getPrivateKey() {
        return this.privateKey;
    }

    public PublicKey getPublicKey() {
        return this.publicKey;
    }

    private PrivateKey getPrivateKey( String key )
        throws InvalidKeySpecException, NoSuchAlgorithmException
    {
        PrivateKey privateKey = null;
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec( Base64.getDecoder().decode( key.getBytes() ) );
        KeyFactory kf = KeyFactory.getInstance( "RSA" );
        privateKey = kf.generatePrivate( spec );

        return privateKey;
    }

    private PublicKey getPublicKey( String key )
        throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        X509EncodedKeySpec X509publicKey = new X509EncodedKeySpec( Base64.getDecoder().decode( key ) );

        KeyFactory kf = KeyFactory.getInstance( "RSA" );

        return kf.generatePublic( X509publicKey );
    }
}
