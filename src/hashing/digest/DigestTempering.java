package hashing.digest;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import encryption.symetric.*;
public class DigestTempering {

	public static void main(String[] args) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
		String input = "Transfer 000100 to AC 12-345";
		SecretKey key = OFBStreamCipher.generateKey(128);
		IvParameterSpec iv = OFBStreamCipher.generateIV();
		byte[] encryptedData = MsgDigest.encryptWithDigest(input.getBytes(), "SHA-1", key, iv);
		
		// tempering the encrypted message
		encryptedData[9] ^= '0'^'9'; // 0 xor k[9] xor 0 xor 9 = k[9] xor 9 decryption k[9] xor 9 xor k[9] = 9
		// tempering the digest
		MessageDigest hash = MessageDigest.getInstance("SHA-1");
		hash.update("Transfer 900100 to AC 12-345".getBytes());
		byte[] temperedHash = hash.digest();
		hash.update("Transfer 000100 to AC 12-345".getBytes());
		byte[] originalHash = hash.digest();
		int digestLength = hash.getDigestLength();
		int d = encryptedData.length;
		for (int i =0; i<digestLength;i++) {
			encryptedData[d-digestLength+i] ^= originalHash[i]^temperedHash[i]; //  originalHash[i] xor k[ originalHash[i]] xor originalHash[i]^temperedHash[i]
		}
		
		String decryptedData = MsgDigest.decryptWithVerification(encryptedData, "SHA-1", key, iv);
		System.out.println("message : "+input );
		System.out.println("encrypted message : " +Utils.toHex(encryptedData) );
		System.out.println(decryptedData);

	}

}
