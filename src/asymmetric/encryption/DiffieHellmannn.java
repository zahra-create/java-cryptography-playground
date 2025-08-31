package asymmetric.encryption;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;

import encryption.symetric.Utils;

public class DiffieHellmannn {

	public static KeyPair generateDHKeyPair(BigInteger p, BigInteger g, SecureRandom randomB) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		KeyPairGenerator gen = KeyPairGenerator.getInstance("DH");
		DHParameterSpec spec = new DHParameterSpec(p,g);
		gen.initialize(spec, randomB);
		return gen.generateKeyPair();
	}
	public static byte[] agreeOnSecret(PrivateKey priv, PublicKey pub) throws NoSuchAlgorithmException, InvalidKeyException, IllegalStateException {
		KeyAgreement agreement = KeyAgreement.getInstance("DH");
		agreement.init(priv); //  b
		agreement.doPhase(pub, true); // g^a mod p 
		return agreement.generateSecret(); 
	}
	
	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalStateException {
		BigInteger g512 = new BigInteger(
				"153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7"
				+ "749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b"
				+ "410b7a0f12ca1cb9a428cc", 16);
		BigInteger p512 = new BigInteger(
				"9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd387"
				+ "44d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94b"
				+ "f0573bf047a3aca98cdf3b", 16);
		SecureRandom randomB = new SecureRandom();
		KeyPair bobPair = generateDHKeyPair(p512, g512,randomB);
		KeyPair alicePair = generateDHKeyPair(p512, g512,randomB);
		byte[] bobSecret = agreeOnSecret(bobPair.getPrivate(),alicePair.getPublic());
		byte[] aliceSecret = agreeOnSecret(alicePair.getPrivate(),bobPair.getPublic());
		System.out.println("secret key (bob side) : "+Utils.toHex(bobSecret));
		System.out.println("secret key (alice side) : "+Utils.toHex(aliceSecret));
	}

}
