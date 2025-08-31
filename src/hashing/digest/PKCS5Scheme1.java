package hashing.digest;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;


import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import encryption.symetric.Utils;

public class PKCS5Scheme1 {

	private static MessageDigest digest;
	public PKCS5Scheme1(MessageDigest digest) {this.digest = digest;}
	
	public static byte[] generatePBKeyBytes(String password, byte[] salt, int iteration) {
		digest.update(password.getBytes());
		digest.update(salt);
		byte[] digestBytes = digest.digest();
		for (int i=1; i<iteration; i++) {
			digest.update(digestBytes);
			digestBytes = digest.digest();
		}
		return digestBytes;
		
	}
	
	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException, NoSuchProviderException {
		Security.addProvider(new BouncyCastleProvider());
		String input = "we are just testing here we are just testing here we are just testing here we are just testing here we are just testing here we are just testing here we are just testing here we are just testing here";
		String password = "password";
		byte[] salt = new byte[8];
		SecureRandom random = new SecureRandom();
		random.nextBytes(salt);
		int iteration = 2000;
		// encryption using java classes
		Cipher cipher = Cipher.getInstance("PBEWithSHA1AndDES", "BC");
		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBEWithSHA1AndDES", "BC");
		PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iteration);
		cipher.init(Cipher.ENCRYPT_MODE, factory.generateSecret(spec));
		byte[] encryptedBytes = cipher.doFinal(input.getBytes());
		// decryption using local class
		MessageDigest digest = MessageDigest.getInstance("SHA1");
		PKCS5Scheme1 scheme = new PKCS5Scheme1(digest);
		byte[] keyBytes = PKCS5Scheme1.generatePBKeyBytes(password, salt, iteration);
		SecretKey key = new SecretKeySpec(keyBytes, 0, 8, "DES");
		IvParameterSpec iv = new IvParameterSpec(keyBytes,8 ,8);
		Cipher decCipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
		decCipher.init(Cipher.DECRYPT_MODE, key, iv);
		byte[] decryptedBytes = decCipher.doFinal(encryptedBytes);
		String decryptedText = new String(decryptedBytes, "UTF-8");
		
		System.out.println("message : "+ input);
		System.out.println("encryptedBytes: "+Utils.toHex(decryptedBytes));
		System.out.println("decrypted bytes : "+ decryptedText);
		
		
		
		
	}
	
}
