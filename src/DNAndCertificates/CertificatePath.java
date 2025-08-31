package DNAndCertificates;

import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import asymmetric.encryption.RSA;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertPath;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;

public class CertificatePath {
	public static X509Certificate[] buildChain(X509Certificate rootCert, X509Certificate issuedCert) {
		return new X509Certificate[] {issuedCert, rootCert};
	}
	public static CertPath createCetPath(X509Certificate[] chain) throws CertificateException, NoSuchProviderException {
		CertificateFactory factory = CertificateFactory.getInstance("X.509", "BC");
		CertPath certPath = factory.generateCertPath(Arrays.asList(chain));
		return certPath;
	}
	public static byte[] encodePathToPem(CertPath certPath) throws CertificateEncodingException {
		return certPath.getEncoded("PEM");
	}
	public static CertPath recoverCertPathFromPem(byte[] pemPathEncoded) throws CertificateException, NoSuchProviderException {
		CertificateFactory factory = CertificateFactory.getInstance("X.509", "BC");
		CertPath certPath = factory.generateCertPath(new ByteArrayInputStream(pemPathEncoded), "PEM");
		return certPath;
	}
	

	public static void main(String[] args) throws InvalidKeyException, IllegalArgumentException, NoSuchAlgorithmException, NoSuchProviderException, IllegalStateException, SignatureException, IOException, InvalidAlgorithmParameterException, CertificateException {
		Security.addProvider(new BouncyCastleProvider());
		KeyPair rootPair = RSA.generateKeys(1024);
		X509Certificate rootCert = X509V1Certificate.generateV1Cert(rootPair);
		KeyPair subjectPair = RSA.generateKeys(1024);
		PKCS10CertificationRequest certRequest = CertificateRequest.generateCertRequest(subjectPair);
		X509Certificate issuedCert = CertificateAuthority.generateCertFromCertRequest(certRequest, rootCert, rootPair.getPrivate());
		X509Certificate[] chain = buildChain(rootCert, issuedCert);
		CertPath certPath = createCetPath(chain);
		byte[] encodedPath = encodePathToPem(certPath);
		String path = new String(encodedPath, "UTF-8");
		System.out.println(path);
		// recover CertPath from PEM encoded CertPath
		CertPath recoveredCertPath = recoverCertPathFromPem(encodedPath);
		System.out.println("CertPath recovered successfully");
		
	}

}
