package encryption.symetric;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
 
// ARC4 stream cipher 
public class StreamCipher {
	// generate key
	public static SecretKey generateKey() {
		byte[] keybytes = new byte[4];
		SecureRandom random = new SecureRandom();
		random.nextBytes(keybytes);
		return new SecretKeySpec(keybytes,"RC4");	
	}
	
	// encrypt
	public static byte[] encrypt(byte[] message, SecretKey key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("RC4");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		return cipher.doFinal(message);
	}
	
	// decrypt 
	public static byte[] decrypt(byte[] ciphermessage, SecretKey key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("RC4");
		cipher.init(Cipher.DECRYPT_MODE, key);
		return cipher.doFinal(ciphermessage);
	}
	
	
	public static void main(String[] args) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		byte[] message = new byte[] {0x3A, 0x3A, 0x3A, 0x3B, (byte)0xC5, 0x3A, 0x3A, 0x3A, (byte)0xE9, 0x0F, 0x3A, 0x3A, 0x3A, 0x71, (byte)0xCE, 0x29, 0x4F};
		SecretKey key = generateKey();
		byte[] ciphermessage = encrypt(message,key);
		byte[] plaintext = decrypt(ciphermessage,key);
		
		System.out.println("clear message : " +Utils.toHex(message));
		System.out.println("encrypted message : " +Utils.toHex(ciphermessage));
		System.out.println("decrypted message : " +Utils.toHex(plaintext));
		System.out.println("size of the message : " +message.length);
		System.out.println("size of the encrypted message : " +ciphermessage.length);

	}

}
