package hashing.digest;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;


import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.util.Arrays;

import encryption.symetric.OFBStreamCipher;
import encryption.symetric.Utils;


public class HMAC {
	private static final String HMAC_ALGORITHM="HmacSHA256";
	
	public static byte[] calculateHMAC(byte[] input, SecretKey key) throws NoSuchAlgorithmException, InvalidKeyException {
		Mac hmac = Mac.getInstance(HMAC_ALGORITHM);
		SecretKeySpec hmacKey = new SecretKeySpec(key.getEncoded(), HMAC_ALGORITHM);
		hmac.init(hmacKey);
		hmac.update(input);
		return hmac.doFinal();
	}
	public static byte[] encrypt(byte[] input, SecretKey key, IvParameterSpec iv) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		byte[] hmacBytes = calculateHMAC(input,key);
		byte[] toBeEncrypted = new byte[input.length+hmacBytes.length];
		System.arraycopy(input, 0, toBeEncrypted, 0, input.length);
		System.arraycopy(hmacBytes, 0, toBeEncrypted, input.length, hmacBytes.length);
		return OFBStreamCipher.encrypt(toBeEncrypted, key, iv);
	}
	public static String decrypt(byte[] encryptedData, SecretKey key, IvParameterSpec iv) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
		byte[] decryptedData = OFBStreamCipher.decrypt(encryptedData, key, iv);
		int hmacLn = Mac.getInstance(HMAC_ALGORITHM).getMacLength();
		byte[] decryptedBytes = Arrays.copyOfRange(decryptedData, 0, decryptedData.length-hmacLn);
		byte[] recievedHmac = Arrays.copyOfRange(decryptedData, decryptedData.length-hmacLn, decryptedData.length);
		byte[] calculatedHmac = calculateHMAC(decryptedBytes, key);
		boolean isNotChanged = MessageDigest.isEqual(recievedHmac, calculatedHmac);
		String message = new String(decryptedBytes, "UTF-8");
		if (isNotChanged) {
			return "decrypted message : "+ message + " verified : True";
		}
		else { 
			return "decrypted message : "+ message + " verified : False";
		}
	}

	public static void main(String[] args) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
		String input = "Transfer 000100 to AC 12-345";
		SecretKey key = OFBStreamCipher.generateKey(256); // remember : key length == produced mac length 
		IvParameterSpec iv = OFBStreamCipher.generateIV();
		byte[] encryptedData = encrypt(input.getBytes(),key,iv);
		// tempering 
		//encryptedData[9] ^= '0'^'9';
		String decryptedData = decrypt(encryptedData,key,iv);
		System.out.println("message : "+input );
		System.out.println("encrypted message : " +Utils.toHex(encryptedData) );
		System.out.println(decryptedData);

	}

}
