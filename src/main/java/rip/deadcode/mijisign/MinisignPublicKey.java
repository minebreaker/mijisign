package rip.deadcode.mijisign;

import rip.deadcode.mijisign.MijisignException.InvalidPublicKeyException;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;

import static rip.deadcode.mijisign.Utils.toHex;

public record MinisignPublicKey(
        String untrustedComment,
        PublicKeyBody publicKey
) {

    public record PublicKeyBody(
            PublicKeySignatureAlgorithm signatureAlgorithm,
            byte[] keyId,
            byte[] publicKey
    ) {}

    public enum PublicKeySignatureAlgorithm {
        Ed25519;

        public static PublicKeySignatureAlgorithm fromBytes( byte upper, byte lower ) throws InvalidPublicKeyException {
            if ( upper == 69 && lower == 100 ) {
                return Ed25519;
            } else {
                var hex = toHex( new byte[] { upper, lower } );
                throw new InvalidPublicKeyException( "Invalid public key signature algorithm: %s".formatted( hex ) );
            }
        }
    }

    public static MinisignPublicKey readPublicKey( Path publicKeyPath ) throws IOException, InvalidPublicKeyException {
        var file = Files.readAllLines( publicKeyPath );
        var lines = file.stream().filter( s -> !s.isBlank() ).toList();
        if ( lines.size() != 2 ) {
            throw new InvalidPublicKeyException( "Invalid format" );
        }
        var untrustedComment = parseUntrustedComment( lines.get( 0 ) );
        var publicKeyBody = parsePublicKeyBody( lines.get( 1 ) );

        return new MinisignPublicKey( untrustedComment, publicKeyBody );
    }

    private static String parseUntrustedComment( String s ) throws InvalidPublicKeyException {
        if ( !s.startsWith( "untrusted comment: " ) ) {
            throw new InvalidPublicKeyException( "Invalid format: untrusted comment" );
        }
        return s.substring( 19 );
    }

    private static PublicKeyBody parsePublicKeyBody( String s ) throws InvalidPublicKeyException {
        try {
            var decoded = ByteBuffer.wrap( Base64.getDecoder().decode( s ) );
            var algorithm = PublicKeySignatureAlgorithm.fromBytes( decoded.get( 0 ), decoded.get( 1 ) );
            var keyId = new byte[8];
            var publicKeyBytes = new byte[decoded.limit() - 10];
            decoded.get( 2, keyId )
                   .get( 10, publicKeyBytes );

            return new PublicKeyBody( algorithm, keyId, publicKeyBytes );

        } catch ( IllegalArgumentException e ) {
            throw new InvalidPublicKeyException( "Invalid format: failed to decode signature from base64", e );
        }
    }

}
