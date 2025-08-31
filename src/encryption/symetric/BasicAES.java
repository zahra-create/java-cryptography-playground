package encryption.symetric;

import java.util.Arrays;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class BasicAES  {
	// secret key generation method
	public static SecretKey generateKey(byte[] keybytes) throws Exception {
		return new SecretKeySpec(keybytes,"AES");
	}
	
	// encryption method
	public static byte[] encrypt(byte[] clearbytes, SecretKey key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		return cipher.doFinal(clearbytes);	
	}
	
	// decryption method
	public static byte[] decrypt(byte[] cipherbytes, SecretKey key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, key);
		return cipher.doFinal(cipherbytes);
	}
	
	public static void main(String[] args) throws Exception {
		byte[] input = new byte[] {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
				                   0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
				                   0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
				                   0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
				                   0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
		// generate the key 
		byte[] keybytes = new byte[] {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x02, 0x03}; // keylength = 16 bytes = 128 bits
		SecretKey key = generateKey(keybytes);
		
		//encrypt the message
		byte[] cipherbytes = encrypt(input,key);
		
		byte[] bankA = new byte[16];
		byte[] accountA = new byte[16];
		byte[] bankB = new byte[16];
		byte[] accountB = new byte[16];
		byte[] dirham = new byte[16];
		byte[] padding = new byte[16];
		
		bankA = Arrays.copyOfRange(cipherbytes, 0, 16);
		accountA = Arrays.copyOfRange(cipherbytes, 16, 32);
		bankB = Arrays.copyOfRange(cipherbytes, 32, 48);
		accountB = Arrays.copyOfRange(cipherbytes, 48, 64);
		dirham  = Arrays.copyOfRange(cipherbytes, 64, 80);
		padding = Arrays.copyOfRange(cipherbytes, 80, 96);
		

		System.out.println("length of cipherbytes : "+ cipherbytes.length);
		System.out.println("encrypted data : "+ Utils.toHex(cipherbytes));
		System.out.println("-------------------------------------------------- ");
		System.out.println("Bank A encrypted block: "+ Utils.toHex(bankA));
		System.out.println("-------------------------------------------------- ");
		System.out.println("Account A encrypted block: "+ Utils.toHex(accountA));
		System.out.println("-------------------------------------------------- ");
		System.out.println("Bank B encrypted block: "+ Utils.toHex(bankB));
		System.out.println("-------------------------------------------------- ");
		System.out.println("Account B encrypted block: "+ Utils.toHex(accountB));
		System.out.println("-------------------------------------------------- ");
		System.out.println("dirhams encrypted block: "+ Utils.toHex(dirham));
		System.out.println("-------------------------------------------------- ");
		System.out.println("padding encrypted block: "+ Utils.toHex(padding));
		
	}
}