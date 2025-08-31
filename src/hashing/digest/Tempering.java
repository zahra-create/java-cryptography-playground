package hashing.digest;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import encryption.symetric.*;

public class Tempering {

	public static void main(String[] args) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
		String input = "Transfer 900100 to AC 12-345";
		
		SecretKey key = OFBStreamCipher.generateKey(128);
		IvParameterSpec iv = OFBStreamCipher.generateIV();
		byte[] encryptedInput = OFBStreamCipher.encrypt(input.getBytes(), key, iv);
		
		// tempering
		encryptedInput[9] ^= '0'^'9';
		
		byte[] decryptedBytes = OFBStreamCipher.decrypt(encryptedInput, key, iv);
		String decryptedText = new String(decryptedBytes, "UTF-8");
		System.out.println("plain text : "+ input);
		System.out.println("encrypted text : "+ Utils.toHex(decryptedBytes));
		System.out.println("decrypted text : "+ decryptedText);

	}

}
