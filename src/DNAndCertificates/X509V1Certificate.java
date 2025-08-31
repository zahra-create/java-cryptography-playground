package DNAndCertificates;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V1CertificateGenerator;

import asymmetric.encryption.RSA;

public class X509V1Certificate {
// TBS
	
	public static X509Certificate generateV1Cert(KeyPair pair) throws InvalidKeyException, NoSuchProviderException, SecurityException, SignatureException {
		X509V1CertificateGenerator certGen = new X509V1CertificateGenerator();
		certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
		certGen.setIssuerDN(new X500Principal("CN=Test Certificate"));
		certGen.setNotBefore(new Date(System.currentTimeMillis() - 50000));
		certGen.setNotAfter(new Date(System.currentTimeMillis() + 50000));
		certGen.setSubjectDN(new X500Principal("CN=Test Certificate"));
		certGen.setPublicKey(pair.getPublic());
		certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");
		return certGen.generateX509Certificate(pair.getPrivate(), "BC");
	}
	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchProviderException, SecurityException, SignatureException, CertificateException {
		Security.addProvider(new BouncyCastleProvider());
		KeyPair pair = RSA.generateKeys(512);
		X509Certificate cert = generateV1Cert(pair);
		cert.checkValidity(new Date());
		cert.verify(cert.getPublicKey());
		System.out.println("valid certificate generated");
		
		System.out.println("signature algorithm : "+cert.getSigAlgName());
	}

}
