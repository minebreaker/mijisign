package rip.deadcode.mijisign;

import javax.annotation.Nullable;

public sealed class MijisignException extends Exception {

    protected MijisignException( @Nullable String message, @Nullable Exception cause ) {
        super( message, cause );
    }

    public static final class InvalidSignatureException extends MijisignException {

        public InvalidSignatureException( @Nullable String message ) {
            super( message, null );
        }

        public InvalidSignatureException( @Nullable String message, @Nullable Exception cause ) {
            super( message, cause );
        }
    }

    public static final class InvalidPublicKeyException extends MijisignException {

        public InvalidPublicKeyException( @Nullable String message ) {
            super( message, null );
        }

        public InvalidPublicKeyException( @Nullable String message, @Nullable Exception cause ) {
            super( message, cause );
        }
    }
}
