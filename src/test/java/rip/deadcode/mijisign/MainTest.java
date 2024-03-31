package rip.deadcode.mijisign;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Paths;

import static com.google.common.truth.Truth.assertThat;
import static rip.deadcode.mijisign.Main.*;
import static rip.deadcode.mijisign.MinisignPublicKey.readPublicKey;
import static rip.deadcode.mijisign.Signature.readSignature;
import static rip.deadcode.mijisign.Verify.verify;

class MainTest {

    @Test
    public void test() throws Exception {

        var signaturePath = Paths.get( SIGNATURE );
        var signature = readSignature( signaturePath );
        var publicKeyPath = Paths.get( PUBLIC_KEY );
        var publicKey = readPublicKey( publicKeyPath );

        var file = Files.readAllBytes( Paths.get( FILE ) );
        var result = verify( signature, publicKey, file );
        assertThat( result ).isTrue();
    }
}
