package DNAndCertificates;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import asymmetric.encryption.RSA;


public class X509V1CertVerification extends X509V1Certificate {
	public static boolean verifyCert(byte[] tbs, byte[] signedTBS, PublicKey pub) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		Signature certVerifier = Signature.getInstance("SHA256withRSA"); 
		certVerifier.initVerify(pub);
		certVerifier.update(tbs);
		return certVerifier.verify(signedTBS);
		
	}

	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchProviderException, SecurityException, SignatureException, CertificateEncodingException {
		Security.addProvider(new BouncyCastleProvider());
		KeyPair rsaPair = RSA.generateKeys(512);
		X509Certificate cert = generateV1Cert(rsaPair);
		byte[] tbs = cert.getTBSCertificate();
		byte[] signedTBS = cert.getSignature();
		System.out.println(verifyCert(tbs,signedTBS,rsaPair.getPublic()));
		
	}

}
