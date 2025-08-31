package asymmetric.encryption;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import encryption.symetric.Utils;

public class RSAPerformance {

	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, NoSuchProviderException {
		BigInteger n = new BigInteger("963b8f10a6182c43848310bc542adf61daff204cb131d8d6e160052b5f2950812ef9a832ee335c5a5a42ec95692eeb66dcf49991479fd857d1480c5eadd768c9", 16);
		BigInteger e = new BigInteger("10001", 16); 
		BigInteger d = new BigInteger("24bccd4c2eb5c01345b310536188b7661459e9b1df6df75efaaf92ac0bc20c619db249d7f46d36d23624d7c2e3d0da8bc2540e1aa7aaeb04d2bfb458d1d05695", 16);
		KeyFactory factory = KeyFactory.getInstance("RSA");
		RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(n,e);
		PublicKey pubKey = factory.generatePublic(pubKeySpec);   
		
		// generate private key without using CRT
		RSAPrivateKeySpec privKeySpec = new RSAPrivateKeySpec(n,d); // !! the private key is larger than the public key
		PrivateKey privKey = factory.generatePrivate(privKeySpec);
		
		//  private key using CRT
		BigInteger p = new BigInteger("e6063d24691582a8451562d38a100ffc18b3b718204bcf7000a96ec12e2798a5", 16);
		BigInteger q = new BigInteger("a732a037b545597fc824b5ca12a7f5583f3c12d9bc1d6ff7f4c69ccee423b255", 16);
		BigInteger dP = d.mod(p.subtract(BigInteger.ONE));
		BigInteger dQ = d.mod(q.subtract(BigInteger.ONE));
		BigInteger qInv = q.modInverse(p);
		RSAPrivateCrtKeySpec privKeyCTRSpec = new RSAPrivateCrtKeySpec(n, e, d, p, q, dP, dQ, qInv);
		PrivateKey privCTRKey = factory.generatePrivate(privKeyCTRSpec);
		
		String input = "hello world! hello world!hello";
		byte [] encrypted = RSA.encrypt(input.getBytes(),pubKey);
		// with CRT
		long startTime = System.nanoTime();
		byte[] decrypted = RSA.decrypt(encrypted, privCTRKey);
		long durationWithCTR = System.nanoTime()-startTime;
		// without CRT
		long startTime2 = System.nanoTime();
		byte[] decrypted2 = RSA.decrypt(encrypted, privKey);
		long durationWithoutCTR = System.nanoTime()-startTime;
		String decryptedText = new String(decrypted, "UTF-8");
		
		System.out.println("duration with CTR: " +durationWithCTR+ " ns");
		System.out.println("duration without CTR: " +durationWithoutCTR+ " ns");
		
 
	}

}
