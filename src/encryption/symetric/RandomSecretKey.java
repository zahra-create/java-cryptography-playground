package encryption.symetric;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class RandomSecretKey {
	 /* there are two ways to generate a secret key randomly : 
	  * generate a random array of bytes and pass it to SecretKeySpec constructor 
	  * use KeyGenerator class pre-built in javax (JCE) 
	   */
	  
	public static Key generateRandomKey(int keyLength) throws NoSuchAlgorithmException {
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(keyLength);
		return keyGen.generateKey();
	}
	
	
	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
		// Generate a secret key
		Key secret = generateRandomKey(128);
		
		// get information about the secret key
		byte[] secretBytes = secret.getEncoded();  // return the array of bytes making up the secret key
		String algorithm = secret.getAlgorithm();   // return the algorithm the secret was made for
		
		// reconstruct the secret key ( this is useful if you want to transmit your key)
		Key reconstructedKey = new SecretKeySpec(secretBytes, algorithm);
		
		
		byte[] data = new byte[36];
		Random random = new Random();
		random.nextBytes(data);
		System.out.println("some bytes data generated randomly : " + Utils.toHex(data));
		
		byte[] encryptedData = BasicAES.encrypt(data, (SecretKey) secret);
		System.out.println("encrypted data using the secret key : " + Utils.toHex(encryptedData));
		byte[] decryptedData = BasicAES.decrypt(encryptedData, (SecretKey) reconstructedKey );
		System.out.println("decrypted data using the reconstructed key : " + Utils.toHex(decryptedData));
		
	}

}
