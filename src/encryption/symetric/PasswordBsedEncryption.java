package encryption.symetric;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class PasswordBsedEncryption {
	
	private static final String ALGORITHM="AES/CBC/PKCS5Padding";
	private static final int SALT_LENGTH = 16;
	private static final int ITERATIONS = 1000;
	private static final int KEY_LENGTH = 128; 

	public static Key generatePBKey(String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
	PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_LENGTH);
	SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
	Key k = factory.generateSecret(keySpec);
	return new SecretKeySpec(k.getEncoded(), "AES");
	}
	
	public static byte[] encrypt(byte[] data, String password) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		// generate random salt
		byte[] salt = new byte[SALT_LENGTH];
		SecureRandom random = new SecureRandom();
		random.nextBytes(salt);
		
		// generate the PBE key
		Key key = generatePBKey(password, salt);
		
		// generate random IV
		byte[] ivbytes = new byte[16];
		SecureRandom r = new SecureRandom();
		r.nextBytes(ivbytes);
		IvParameterSpec iv = new IvParameterSpec(ivbytes);
		
		// create cipher object to encrypt the data
		Cipher cipher = Cipher.getInstance(ALGORITHM);
		cipher.init(Cipher.ENCRYPT_MODE, key, iv);
		byte[] encryptedData = cipher.doFinal(data);
		
		// return data, salt, and iv
		byte[] encrypted = new byte[encryptedData.length + salt.length + ivbytes.length];
		System.arraycopy(salt, 0, encrypted, 0, salt.length);
		System.arraycopy(ivbytes, 0, encrypted, salt.length, ivbytes.length);
		System.arraycopy(encryptedData, 0, encrypted, salt.length+ivbytes.length, encryptedData.length);
		return encrypted;
	}
	
	public static byte[] decrypt(byte[] cipherbytes, String password) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException {
		// retrieve the salt from cipherbytes and generate the key
		byte[] salt = Arrays.copyOfRange(cipherbytes, 0 ,SALT_LENGTH);
		Key key = generatePBKey(password, salt);
		
		// retrieve the ivbytes and generate the IV
		byte[] ivbytes = Arrays.copyOfRange(cipherbytes, SALT_LENGTH, SALT_LENGTH+16);
		IvParameterSpec iv = new IvParameterSpec(ivbytes);
		
		// retrieve the encryptedData
		byte[] encryptedData = Arrays.copyOfRange(cipherbytes, SALT_LENGTH+16, cipherbytes.length);
		
		// decryption
		Cipher cipher = Cipher.getInstance(ALGORITHM);
		cipher.init(Cipher.DECRYPT_MODE, key, iv);
		return cipher.doFinal(encryptedData);
	}
	
	public static void main(String[] args) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		byte[] data = {0x35, 0x0A, 0x01, 0x3B, (byte)0xC5, 0x3A, 0x3A, 0x3A, (byte)0xE9, 0x0F, 0x3A, 0x3A, 0x3A, 0x71, (byte)0xCE, 0x29, 0x4F};
		String password = "password123";
		byte[] encryptedData = encrypt(data,password);
		byte[] decryptedData = decrypt(encryptedData, password);
		byte[] salt = Arrays.copyOfRange(encryptedData, 0, SALT_LENGTH);
		byte[] IVbytes = Arrays.copyOfRange(encryptedData, SALT_LENGTH, SALT_LENGTH+16);
		
		
		System.out.println("original data : "+ Utils.toHex(data));
		System.out.println("decryptedData : "+ Utils.toHex(decryptedData));
		System.out.println("encryptedData : "+ Utils.toHex(encryptedData));
		System.out.println("salt : "+ Utils.toHex(salt));
		System.out.println("IV bytes : "+ Utils.toHex(IVbytes));

	}

}
