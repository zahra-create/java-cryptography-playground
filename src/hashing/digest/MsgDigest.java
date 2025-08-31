package hashing.digest;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import encryption.symetric.*;

public class MsgDigest {
	
	public static byte[] mDigest(byte[] input, String hashFunction) throws NoSuchAlgorithmException {
		MessageDigest hash = MessageDigest.getInstance(hashFunction);
		hash.update(input);
		return hash.digest();
	}
	public static byte[] encryptWithDigest(byte[] input, String hashF, SecretKey key, IvParameterSpec iv) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		byte[] hashedMessage = mDigest(input, hashF);
		byte[] toBeEncrypted = new byte[hashedMessage.length+input.length];
		System.arraycopy(input, 0, toBeEncrypted, 0, input.length);
		System.arraycopy(hashedMessage, 0, toBeEncrypted, input.length, hashedMessage.length);
		
		return OFBStreamCipher.encrypt(toBeEncrypted, key, iv);
	}
	public static String decryptWithVerification(byte[] encryptedBytes, String hashF, SecretKey key, IvParameterSpec iv) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
		MessageDigest hash = MessageDigest.getInstance(hashF);	
		byte[] decrypted = OFBStreamCipher.decrypt(encryptedBytes, key, iv);
		int hashLength = hash.getDigestLength();
		byte[] recievedText = Arrays.copyOfRange(decrypted, 0, decrypted.length-hashLength);
		byte[] recievedDigest = Arrays.copyOfRange(decrypted, decrypted.length - hashLength, decrypted.length);
		
		
		// compute the hash of recieved message
		hash.update(recievedText);
		byte[] computedHash = hash.digest();
		
		String message = new String(recievedText, "UTF-8");
		boolean isNotChanged = MessageDigest.isEqual(recievedDigest, computedHash);
		if (isNotChanged) {
			return "decrypted message : "+ message + " verified : True";
		}
		else { 
			return "decrypted message : "+ message + " verified : False";
		}
		
	}
	public static void main(String[] args) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
		String input = "Transfer 000100 to AC 12-345";
		SecretKey key = OFBStreamCipher.generateKey(128);
		IvParameterSpec iv = OFBStreamCipher.generateIV();
		byte[] encryptedData = encryptWithDigest(input.getBytes(), "SHA-1", key, iv);
		
		// tempering 
		encryptedData[9] ^= '0'^'9';
		
		String decryptedData = decryptWithVerification(encryptedData, "SHA-1", key, iv);
		System.out.println("message : "+input );
		System.out.println("encrypted message : " +Utils.toHex(encryptedData) );
		System.out.println(decryptedData);

	}

}
