package rip.deadcode.mijisign;

public final class Utils {

    public static String toHex( byte[] bytes ) {
        StringBuilder sb = new StringBuilder( bytes.length * 2 );
        for ( byte b : bytes ) {
            sb.append( String.format( "%02x", b ) );
        }
        return sb.toString();
    }

    public static byte[] reverse( byte[] bytes ) {
        var newBytes = new byte[bytes.length];
        for ( int i = 0; i < bytes.length; i++ ) {
            newBytes[i] = bytes[bytes.length - i - 1];
        }
        return newBytes;
    }
}
