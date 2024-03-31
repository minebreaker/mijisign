package rip.deadcode.mijisign;

import java.nio.file.Files;
import java.nio.file.Paths;

import static rip.deadcode.mijisign.MinisignPublicKey.readPublicKey;
import static rip.deadcode.mijisign.Signature.readSignature;
import static rip.deadcode.mijisign.Utils.toHex;
import static rip.deadcode.mijisign.Verify.verify;

public final class Main {

    public static void main( String[] args ) throws Exception {

        var signaturePath = Paths.get( SIGNATURE );
        var signature = readSignature( signaturePath );
        show( signature );
        var publicKeyPath = Paths.get( PUBLIC_KEY );
        var publicKey = readPublicKey( publicKeyPath );
        show( publicKey );

        var file = Files.readAllBytes( Paths.get( FILE ) );
        var result = verify( signature, publicKey, file );
        if ( result ) {
            System.out.println( "Successfully verified." );
        } else {
            System.out.println( "Verification failed." );
        }
    }

    public static final String SIGNATURE = "./test/test.txt.minisig";
    public static final String PUBLIC_KEY = "./test/minisign.pub";
    public static final String FILE = "./test/test.txt";

    private static void show( Signature s ) {
        System.out.println( "untrusted comment: " + s.untrustedComment() );
        System.out.printf(
                "signature: alg: %s, key id: %s, signature: %s%n",
                s.signature().signatureAlgorithm(),
                toHex( s.signature().keyId() ),
                toHex( s.signature().signature() )
        );
        System.out.println( "trusted comment: " + s.trustedComment() );
        System.out.println( "global signature: " + toHex( s.globalSignature() ) );
    }

    private static void show( MinisignPublicKey pk ) {
        System.out.println( "untrusted comment: " + pk.untrustedComment() );
        System.out.printf(
                "signature: alg: %s, key id: %s, signature: %s%n",
                pk.publicKey().signatureAlgorithm(),
                toHex( pk.publicKey().keyId() ),
                toHex( pk.publicKey().publicKey() )
        );
    }
}
