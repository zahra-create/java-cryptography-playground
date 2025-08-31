package diffieHellman.aes;

import java.math.BigInteger;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class DHAes {
	
	private static final int AES_KEY_LENGTH = 128; 
	protected static final DHParameterSpec dhSpec; // the prime p and the primitive element g
	
	protected KeyPair keyPair;
	private KeyAgreement keyAgreement;
	private SecretKey aesKey;
	
    static {
        try {
            AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DiffieHellman");
            paramGen.init(2048); // Key size (must be multiple of 64)
            AlgorithmParameters params = paramGen.generateParameters();
            dhSpec = params.getParameterSpec(DHParameterSpec.class);
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize DH parameters", e);
        }
    }
	
	// by the end of this constructor keyPair and keyAgreement attributes will be initialized
	DHAes() throws Exception {
		
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DiffieHellman");
		SecureRandom random = new SecureRandom();
		keyPairGenerator.initialize(dhSpec, random);
		keyPair =  keyPairGenerator.generateKeyPair();
		
		keyAgreement = KeyAgreement.getInstance("DiffieHellman");
		keyAgreement.init(keyPair.getPrivate());
		
	}
	
	public PublicKey getPublicKey() {
		
		return keyPair.getPublic();		
	}
	
	
	public byte[] getDHSharedKey(PublicKey pk) throws Exception {
		
		keyAgreement.doPhase(pk, true);
		byte[] dhSharedSecret = keyAgreement.generateSecret();
		return  dhSharedSecret;	
	}
	
	// this method set the aesKey attribute
	public void setaesKey(PublicKey pk) throws Exception {
		// compute the DH shared secret 
		byte[] dhSharedSecret = this.getDHSharedKey(pk);
		
		byte[] neededBytes = new byte[AES_KEY_LENGTH/8];
	    System.arraycopy(dhSharedSecret, 0, neededBytes, 0, neededBytes.length);
	    
	    // Create AES key  
	    aesKey =  new SecretKeySpec(neededBytes, "AES");
	    
	}
	
	public byte[] encrypt(String plaintext) throws Exception {
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(cipher.ENCRYPT_MODE, aesKey);
		return cipher.doFinal(plaintext.getBytes());

	}
	
	public String decrypt(byte[] ciphertext) throws Exception {
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(cipher.DECRYPT_MODE, aesKey);
		return new String(cipher.doFinal(ciphertext), "UTF-8");
	}
	
	
	public static void main(String[] args) throws Exception {
		DHAes alice = new DHAes();
		DHAes bob = new DHAes();
		PublicKey alice_pk = alice.getPublicKey();
		PublicKey bob_pk = bob.getPublicKey();
		alice.setaesKey(bob_pk);
		bob.setaesKey(alice_pk);
		String plaintext = "Hey alice! i am bob.";
		byte[] ciphertext = bob.encrypt(plaintext);
		String decryptedText = alice.decrypt(ciphertext);
		System.out.println("alice recieved this message from bob : "+decryptedText);
	}
	
	
	
	

}
