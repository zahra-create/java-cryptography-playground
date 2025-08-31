package encryption.symetric;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;

import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
public class KeyWrapping {
	
	public static  Key generateKey(int length) throws NoSuchAlgorithmException {
		KeyGenerator generator = KeyGenerator.getInstance("AES");
		generator.init(length);
		return generator.generateKey();	}
	
	public static byte[] wrap(Key wrappingKey, Key keyToWrap) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchProviderException {
		Cipher wrapper = Cipher.getInstance("AESWrap"); // use AES algorithm to wrap ( = to encrypt the DEK)
		wrapper.init(Cipher.WRAP_MODE, wrappingKey);
		return wrapper.wrap(keyToWrap);
	}
	
	public static Key unwrap(Key wrappingKey, byte[] wrappedKey) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException {
		Cipher unrapper = Cipher.getInstance("AESWrap"); // use AES algorithm to unwrap ( = to decrypt the DEK)
		unrapper.init(Cipher.UNWRAP_MODE, wrappingKey);
		return unrapper.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY); // Cipher.SECRET_KEY == 3, it indicates that type of the key is symmetric key
	}
	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchProviderException {
		
		Key keyTowrap = generateKey(128);
		Key wrapKey = generateKey(192);
		byte[] wrappedKey = wrap(wrapKey,keyTowrap);
		Key unwrappedKey = unwrap(wrapKey,wrappedKey);
		
		System.out.println("Key to wrap : "+Utils.toHex(keyTowrap.getEncoded()));
		System.out.println("wrapped Key : "+Utils.toHex(wrappedKey));
		System.out.println("unwrapped Key : "+Utils.toHex(unwrappedKey.getEncoded()));
		
		
	}

}
