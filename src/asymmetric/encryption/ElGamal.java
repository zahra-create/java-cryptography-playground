package asymmetric.encryption;

import java.io.UnsupportedEncodingException;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.DHParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import encryption.symetric.Utils;

public class ElGamal {
	public static KeyPair generateElgamalPair(SecureRandom random) throws NoSuchAlgorithmException, InvalidParameterSpecException, InvalidAlgorithmParameterException, NoSuchProviderException {
		// create parameters
		AlgorithmParameterGenerator apg = AlgorithmParameterGenerator.getInstance("ElGamal", "BC");
		apg.init(256, random);
		AlgorithmParameters params = apg.generateParameters();
		AlgorithmParameterSpec dhSpec = params.getParameterSpec(DHParameterSpec.class);
		// generate key
		KeyPairGenerator gen = KeyPairGenerator.getInstance("ELGamal");
		gen.initialize(dhSpec);
		return gen.generateKeyPair();
	}
	public static byte[] encrypt(byte[] input, Key pubKey) throws NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, NoSuchPaddingException {
		Cipher cipher = Cipher.getInstance("ElGamal/None/NoPadding", "BC"); 
		cipher.init(Cipher.ENCRYPT_MODE, pubKey);
		return cipher.doFinal(input);
	}
	public static byte[] decrypt(byte[] encrypted, Key privKey) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchProviderException {
		Cipher cipher = Cipher.getInstance("ElGamal/None/NoPadding", "BC");
		cipher.init(Cipher.DECRYPT_MODE, privKey);
		return cipher.doFinal(encrypted);}

	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidParameterSpecException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, NoSuchPaddingException, UnsupportedEncodingException {
		Security.addProvider(new BouncyCastleProvider());
		String input = "  world!hello hello world!";
		SecureRandom random = new SecureRandom();
		KeyPair pair = generateElgamalPair(random);
		byte[] encrypted = encrypt(input.getBytes(),pair.getPublic());
		byte[] decrypted = decrypt(encrypted, pair.getPrivate());
		String decryptedText = new String(decrypted, "UTF-8");
		System.out.println("plain text  : "+input);
		System.out.println("encrypted data : "+Utils.toHex(decrypted));
		System.out.println("decrypted text : "+decryptedText);
		

	}

}
