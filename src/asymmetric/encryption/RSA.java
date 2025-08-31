package asymmetric.encryption;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import encryption.symetric.Utils;

import java.security.Security;
import java.security.spec.RSAKeyGenParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
/*
 * problems without padding : 1- leading zeros padding. 2- small e and M 
 * the padding serves to : 1- protect leading zeros. 2- make M larger and closer to n, so that M^e is greater than the modulo n 
 * padding algorithms : 1- PKCS1 (type 1 for signature and type 2 for encryption). 2- OAEP (for encryption). 3- PSS ( for signature)
 */

public class RSA {
	public static byte[] encrypt(byte[] input, Key pubKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException {
		Cipher cipher = Cipher.getInstance("RSA/None/OAEPWithSHA1AndMGF1Padding", "BC"); 
		cipher.init(Cipher.ENCRYPT_MODE, pubKey);
		return cipher.doFinal(input);
	}
	public static byte[] decrypt(byte[] encrypted, Key privKey) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchProviderException {
		Cipher cipher = Cipher.getInstance("RSA/None/OAEPWithSHA1AndMGF1Padding", "BC");
		cipher.init(Cipher.DECRYPT_MODE, privKey);
		return cipher.doFinal(encrypted);
	}
	// generate random keys
	public static KeyPair generateKeys(int length) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		byte[] arr = new byte[12];
		SecureRandom random = new SecureRandom();
		random.nextBytes(arr);
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(new RSAKeyGenParameterSpec(length, RSAKeyGenParameterSpec.F0), random); // F0 means e = 3
		return generator.generateKeyPair();
	}

	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, NoSuchProviderException, InvalidAlgorithmParameterException {
		Security.addProvider(new BouncyCastleProvider());
		byte[] input = new byte[] { 0x00, (byte)0xbe, (byte)0xef };; // input == 00beef
		KeyPair pair = generateKeys(512);
		Key pubKey = pair.getPublic();
		Key privKey = pair.getPrivate();
		byte [] encrypted = encrypt(input,pubKey);
		byte[] decrypted = decrypt(encrypted, privKey);
		System.out.println(Utils.toHex(input));
		System.out.println(Utils.toHex(encrypted));
		System.out.println(Utils.toHex(decrypted));
	
	
		// 00beef^3 mod n = 00beef^3 = C ---- triple_root(C) = M | c^d mod n

	}

}
