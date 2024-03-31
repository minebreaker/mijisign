package rip.deadcode.mijisign;

import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.jcajce.provider.digest.Blake2b;

public final class Verify {

    public static boolean verify( Signature signature, MinisignPublicKey publicKey, byte[] file ) throws MijisignException.InvalidPublicKeyException {
        switch ( signature.signature().signatureAlgorithm() ) {
        case Ed25519, Ed25519Legacy -> {
            // Verify signature
            var signedBytes = switch ( signature.signature().signatureAlgorithm() ) {
                case Ed25519 -> blake2b( file );
                case Ed25519Legacy -> file;
            };
            var signer = new Ed25519Signer();
            signer.init( false, new Ed25519PublicKeyParameters( publicKey.publicKey().publicKey() ) );
            signer.update( signedBytes, 0, signedBytes.length );
            var isValidSignature = signer.verifySignature( signature.signature().signature() );

            // Verify trusted comment

            return isValidSignature;
        }
        }
        throw new Error( "Unreachable" );
    }

    private static byte[] blake2b( byte[] bytes ) {
        return new Blake2b.Blake2b512().digest( bytes );
    }
}
