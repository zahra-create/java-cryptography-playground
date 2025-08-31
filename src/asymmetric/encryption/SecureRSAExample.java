package asymmetric.encryption;

import java.security.*;
import java.security.spec.*;
import java.math.BigInteger;

public class SecureRSAExample {
    public static void main(String[] args) throws Exception {
        // Use KeyPairGenerator to create a secure RSA key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(512); // Minimum secure size (but still weak; use 2048+ in production)
        KeyPair keyPair = keyGen.generateKeyPair();

        // Extract public and private keys
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // Get the RSA parameters (n, e, d, p, q, etc.)
        RSAPublicKeySpec publicKeySpec = KeyFactory.getInstance("RSA")
            .getKeySpec(publicKey, RSAPublicKeySpec.class);
        RSAPrivateCrtKeySpec privateKeySpec = KeyFactory.getInstance("RSA")
            .getKeySpec(privateKey, RSAPrivateCrtKeySpec.class);

        // Print the key parameters (hex format)
        System.out.println("Modulus (n): " + publicKeySpec.getModulus().toString(16));
        System.out.println("Public exponent (e): " + publicKeySpec.getPublicExponent().toString(16));
        System.out.println("Private exponent (d): " + privateKeySpec.getPrivateExponent().toString(16));
        System.out.println("Prime p: " + privateKeySpec.getPrimeP().toString(16));
        System.out.println("Prime q: " + privateKeySpec.getPrimeQ().toString(16));
    }
}


