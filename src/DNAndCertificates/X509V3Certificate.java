package DNAndCertificates;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
//import java.security.cert.X509Extension;
import java.util.Date;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.x509.X509V3CertificateGenerator;

import asymmetric.encryption.RSA;

public class X509V3Certificate {
	public static X509Certificate generateV3cert(KeyPair pair) throws CertificateEncodingException, InvalidKeyException, IllegalStateException, NoSuchAlgorithmException, SignatureException {
		X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
		certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
		certGen.setIssuerDN(new X500Principal("CN=Test certificate"));
		certGen.setNotBefore(new Date(System.currentTimeMillis()-50000));
		certGen.setNotAfter(new Date(System.currentTimeMillis()+50000));
		certGen.setSubjectDN(new X500Principal("CN=Test certificate"));
		certGen.setPublicKey(pair.getPublic());
		certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");
		
		certGen.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false)); // this extension means that this certificate cant be used to sign another certificate
		certGen.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment)); // cert can be used for digital signature or key encryption
		certGen.addExtension(X509Extensions.ExtendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth)); // cert use case extended to serverAuth
		certGen.addExtension(X509Extensions.SubjectAlternativeName, false, new GeneralNames(new GeneralName(GeneralName.rfc822Name, "test@test.test"))); // the cert certifies many names 
		return certGen.generate(pair.getPrivate());
	}

	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, CertificateException, NoSuchProviderException, SignatureException {
		Security.addProvider(new BouncyCastleProvider());
		KeyPair pair = RSA.generateKeys(512);
		X509Certificate cert = generateV3cert(pair);
		cert.checkValidity(new Date());
		cert.verify(cert.getPublicKey());
		System.out.println("valid certificate generated");

	}

}
