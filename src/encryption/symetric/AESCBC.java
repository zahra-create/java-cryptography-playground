package encryption.symetric;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;
public class AESCBC {

	// secret key generation method
	public static SecretKey generateKey(int length) throws Exception {
		byte[] key = new byte[length/8];
		SecureRandom random = new SecureRandom();
		random.nextBytes(key);
		return new SecretKeySpec(key,"AES");
	}
	//random iv generation
	public static IvParameterSpec generateRandomIV() {
		byte[] iv = new byte[16];
		SecureRandom random = new SecureRandom();
		random.nextBytes(iv);
		return new IvParameterSpec(iv);
	}
	// encryption method
	public static byte[] encrypt(byte[] clearbytes, SecretKey key, IvParameterSpec iv) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, key,iv);
		return cipher.doFinal(clearbytes);	
	}
	// decryption method
	public static byte[] decrypt(byte[] cipherbytes, SecretKey key, IvParameterSpec iv) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, InvalidAlgorithmParameterException {
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, key, iv);
		return cipher.doFinal(cipherbytes);
	}
	
	
	public static void main(String[] args) throws Exception {
		byte[] input = new byte[] {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
		// generate the key 
		
		SecretKey key = generateKey(128);
		// generate the IV NOT RANDOMLY
		/*byte[] ivbytes = new byte[] {0x01, 0x04, 0x02, 0x10, 0x04, 0x09, 0x08, 0x07,
				0x05, 0x09, 0x01, 0x02, 0x04, 0x05, 0x0a, 0x0b};
		IvParameterSpec iv = new IvParameterSpec(ivbytes);*/
		// generate the IV BUT RANDOMLY
		IvParameterSpec iv = generateRandomIV();
		//encrypt the message
		byte[] cipherbytes = encrypt(input,key,iv);
		
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
		dirham = Arrays.copyOfRange(cipherbytes, 64, 80);
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
