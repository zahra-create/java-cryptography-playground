package asymmetric.encryption;

import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.DSAParameterSpec;
import java.security.spec.InvalidParameterSpecException;

public class DigitalSignature {

	
	public static  KeyPair generatePair(SecureRandom random) throws NoSuchAlgorithmException, InvalidParameterSpecException, InvalidAlgorithmParameterException {
		AlgorithmParameterGenerator apg = AlgorithmParameterGenerator.getInstance("DSA");
		apg.init(512, random);
		AlgorithmParameters params = AlgorithmParameters.getInstance("DSA");
		params = apg.generateParameters();
		AlgorithmParameterSpec dsaSpec = params.getParameterSpec(DSAParameterSpec.class);
		KeyPairGenerator gen = KeyPairGenerator.getInstance("DSA");
		gen.initialize(dsaSpec);
		return gen.generateKeyPair();
	}
	public static byte[] doSign(byte[] message, PrivateKey priv) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		Signature signer = Signature.getInstance("DSA");
		signer.initSign(priv);
		signer.update(message);
		return signer.sign();
	}
	public static boolean doVerify(byte[] signed, byte[] message, PublicKey pub) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		Signature verifier = Signature.getInstance("DSA");
		verifier.initVerify(pub);
		verifier.update(message);
		return verifier.verify(signed);
	}
	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidParameterSpecException, InvalidAlgorithmParameterException, InvalidKeyException, SignatureException {
		String message = "a string to sign and verify";
		String message2 = "a string to sign and verify.";
		KeyPair pair = generatePair(new SecureRandom());
		byte[] signed = doSign(message.getBytes(),pair.getPrivate());
		boolean isValid = doVerify(signed,message2.getBytes(),pair.getPublic());
		System.out.println("the signature verification is : "+isValid);

	}

}
