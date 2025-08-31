package encryption.symetric;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class OFBStreamCipher {
	// generate the key
	public static SecretKey generateKey(int keyLength) {
		byte[] keybytes = new byte[keyLength/8];
		SecureRandom random = new SecureRandom();
		random.nextBytes(keybytes);
		return new SecretKeySpec(keybytes, "AES");
	}
	
	// generate the iv
	public static IvParameterSpec generateIV() {
		byte[] ivbytes = new byte[16];
		SecureRandom random = new SecureRandom();
		random.nextBytes(ivbytes);
		return new IvParameterSpec(ivbytes);
	}
	
	// encrypt
	public static byte[] encrypt(byte[] message, SecretKey key, IvParameterSpec iv) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("AES/OFB/NoPadding");
		cipher.init(Cipher.ENCRYPT_MODE, key, iv);
		return cipher.doFinal(message);			
	}
	
	// decrypt 
	public static byte[] decrypt(byte[] ciphermessage, SecretKey key, IvParameterSpec iv) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("AES/OFB/NoPadding");
		cipher.init(Cipher.DECRYPT_MODE, key, iv);
		return cipher.doFinal(ciphermessage);			
	}
	public static void main(String[] args) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		byte[] message = new byte[] {0x3A, (byte) 0xFF, 0x1B, 0x7E, (byte)0xC5, (byte)0x90, 0x2D, 0x64, (byte)0xE9, 0x0F, (byte)0x8A, 0x53, (byte)0xBD, 0x71, (byte)0xCE, 0x29, 0x4F};
		SecretKey key = generateKey(128);
		IvParameterSpec iv = generateIV();
		byte[] ciphermessage = encrypt(message,key,iv);
		
		System.out.println("The length of encrypted data : " + ciphermessage.length);
		System.out.println("The length of data : " + message.length);
		System.out.println("clear data : "+ Utils.toHex(message));
		System.out.println("encrypted data : "+ Utils.toHex(ciphermessage));
	}

}
