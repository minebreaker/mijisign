package rip.deadcode.mijisign;

import rip.deadcode.mijisign.MijisignException.InvalidSignatureException;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;

import static rip.deadcode.mijisign.Utils.toHex;

public record Signature(
        String untrustedComment,
        SignatureBody signature,
        String trustedComment,
        byte[] globalSignature
) {

    public record SignatureBody(
            SignatureAlgorithm signatureAlgorithm,
            byte[] keyId,
            byte[] signature
    ) {}

    public enum SignatureAlgorithm {
        Ed25519,
        Ed25519Legacy;

        public static SignatureAlgorithm fromBytes( byte upper, byte lower ) throws InvalidSignatureException {
            if ( upper == 69 && lower == 68 ) {
                return Ed25519;
            } else if ( upper == 69 && lower == 100 ) {
                return Ed25519Legacy;
            } else {
                var hex = toHex( new byte[] { upper, lower } );
                throw new InvalidSignatureException( "Invalid signature algorithm: %s".formatted( hex ) );
            }
        }
    }


    public static Signature readSignature( Path signaturePath ) throws IOException, InvalidSignatureException {
        var file = Files.readAllLines( signaturePath );
        var lines = file.stream().filter( s -> !s.isBlank() ).toList();
        if ( lines.size() != 4 ) {
            throw new InvalidSignatureException( "Invalid format" );
        }
        var untrustedComment = parseUntrustedComment( lines.get( 0 ) );
        var signatureBody = parseSignatureBody( lines.get( 1 ) );
        var trustedComment = parseTrustedComment( lines.get( 2 ) );
        var globalSignature = parseGlobalSignature( lines.get( 3 ) );

        return new Signature(
                untrustedComment,
                signatureBody,
                trustedComment,
                globalSignature
        );
    }

    private static String parseUntrustedComment( String s ) throws InvalidSignatureException {
        if ( !s.startsWith( "untrusted comment: " ) ) {
            throw new InvalidSignatureException( "Invalid format: untrusted comment" );
        }
        return s.substring( 19 );
    }

    private static String parseTrustedComment( String s ) throws InvalidSignatureException {
        if ( !s.startsWith( "trusted comment: " ) ) {
            throw new InvalidSignatureException( "Invalid format: trusted comment" );
        }
        return s.substring( 17 );
    }

    private static SignatureBody parseSignatureBody( String s ) throws InvalidSignatureException {
        try {
            var decoded = ByteBuffer.wrap( Base64.getDecoder().decode( s ) );
            var algorithm = SignatureAlgorithm.fromBytes( decoded.get( 0 ), decoded.get( 1 ) );
            var keyId = new byte[8];
            var signatureBytes = new byte[decoded.limit() - 10];
            decoded.get( 2, keyId )
                   .get( 10, signatureBytes );

            return new SignatureBody( algorithm, keyId, signatureBytes );

        } catch ( IllegalArgumentException e ) {
            throw new InvalidSignatureException( "Invalid format: failed to decode signature from base64", e );
        }
    }

    private static byte[] parseGlobalSignature( String s ) throws InvalidSignatureException {
        try {
            return Base64.getDecoder().decode( s );
        } catch ( IllegalArgumentException e ) {
            throw new InvalidSignatureException( "Invalid format: failed to decode global signature from base64", e );
        }
    }
}
