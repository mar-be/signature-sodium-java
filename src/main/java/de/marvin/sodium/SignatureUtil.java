package de.marvin.sodium;

import com.goterl.lazycode.lazysodium.LazySodiumJava;
import com.goterl.lazycode.lazysodium.SodiumJava;
import com.goterl.lazycode.lazysodium.exceptions.SodiumException;
import com.goterl.lazycode.lazysodium.interfaces.Sign;
import com.goterl.lazycode.lazysodium.utils.Key;
import com.goterl.lazycode.lazysodium.utils.KeyPair;

import java.io.*;

import static de.marvin.sodium.KeyIO.writeKeyToFile;

public class SignatureUtil {

    private static LazySodiumJava lazySodium = new LazySodiumJava(new SodiumJava());

    public static void generateSigningKeys() throws SodiumException, IOException {
        KeyPair kp = lazySodium.cryptoSignKeypair();
        Key publicKey = kp.getPublicKey();
        Key secretKey = kp.getSecretKey();
        if (!lazySodium.cryptoSignKeypair(publicKey.getAsBytes(), secretKey.getAsBytes())) {
            throw new SodiumException("Could not generate a signing keypair.");
        }
        writeKeyToFile(publicKey, "public.key");
        writeKeyToFile(secretKey, "secret.key");
    }

    public static byte[] sign(byte[] messageBytes, Key secretKey){
        return sign(messageBytes, secretKey.getAsBytes());
    }

    public static boolean verifySign(byte[] messageBytes, byte[] signature, Key publicKey){
        return verifySign(messageBytes, signature, publicKey.getAsBytes());
    }

    public static byte[] sign(byte[] messageBytes, byte[] secretKey){
        byte[] signatureBytes = new byte[Sign.BYTES];
        lazySodium.cryptoSignDetached(signatureBytes, messageBytes, messageBytes.length,  secretKey);
        return signatureBytes;
    }

    public static boolean verifySign(byte[] messageBytes, byte[] signature, byte[] publicKey){
        return lazySodium.cryptoSignVerifyDetached(signature, messageBytes, messageBytes.length, publicKey);
    }
}
