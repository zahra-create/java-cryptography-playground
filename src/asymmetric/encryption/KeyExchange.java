package asymmetric.encryption;
import java.security.KeyPair;
import java.security.Security;


import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import encryption.symetric.*;



public class KeyExchange {
	public static byte[] mergeKeyandIV(SecretKey key, IvParameterSpec iv) {
		byte[] keyBytes = key.getEncoded();
		byte[] ivBytes = iv.getIV();
		byte[] KeyIV = new byte[keyBytes.length+ivBytes.length];
		System.arraycopy(keyBytes, 0, KeyIV, 0, keyBytes.length);
		System.arraycopy(ivBytes, 0, KeyIV, keyBytes.length, ivBytes.length);
		return KeyIV;
		
	}
	public static Object[] separateKeyIv(byte[] KeyIV) {
		
		return new Object[] {new SecretKeySpec(KeyIV, 0, KeyIV.length-16, "AES"), 
				new IvParameterSpec(KeyIV, KeyIV.length-16, 16)};	
	}
																
	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		String Bobmessage = "hello world hello worldhello worldhello worldhello worldhello worldhello worldhello worldhello worldhello world";
		SecretKey key = AESCBC.generateKey(128);
		IvParameterSpec iv = AESCBC.generateRandomIV();
		KeyPair pair = RSA.generateKeys(1024);
		// Bob side
		byte[] wrappedSecretKey = RSA.encrypt(mergeKeyandIV(key,iv), pair.getPublic());
		byte[] encryptedMessage = AESCBC.encrypt(Bobmessage.getBytes(), key, iv);
		// Alice side
		Object[] keyIV = separateKeyIv(RSA.decrypt(wrappedSecretKey, pair.getPrivate()));
		byte[] decryptedMessage = AESCBC.decrypt(encryptedMessage, (SecretKey)keyIV[0],(IvParameterSpec) keyIV[1]);
		
		String msg = new String(decryptedMessage, "UTF-8");
		System.out.println(msg);
		
		

	}

}
