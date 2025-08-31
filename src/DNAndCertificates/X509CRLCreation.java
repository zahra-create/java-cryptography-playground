package DNAndCertificates;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V2CRLGenerator;

import asymmetric.encryption.RSA;

public class X509CRLCreation {
	
	public static X509CRL createCRL(X509Certificate CACert, PrivateKey CAPrivateKey, BigInteger RevokedSN) throws InvalidKeyException, CRLException, IllegalStateException, NoSuchAlgorithmException, SignatureException, CertificateEncodingException {
		X509V2CRLGenerator gen = new X509V2CRLGenerator();
		Date now = new Date();
		gen.setThisUpdate(now);
		gen.setNextUpdate(new Date(now.getTime()+10000));
		gen.setIssuerDN(CACert.getIssuerX500Principal());
		gen.setSignatureAlgorithm("SHA256WithRSAEncryption");
		// revoked certificates
		gen.addCRLEntry(RevokedSN, now, CRLReason.privilegeWithdrawn);
		
		// extensions
		gen.addExtension(X509Extension.cRLNumber, false, new CRLNumber(BigInteger.valueOf(2)));
		gen.addExtension(X509Extension.authorityKeyIdentifier, false, new AuthorityKeyIdentifier(CACert.getEncoded()));
		
		return gen.generate(CAPrivateKey);
	}
	public static X509CRL reconstructEncodedCRL(byte[] encodedCRL) throws CertificateException, CRLException {
		ByteArrayInputStream bIn = new ByteArrayInputStream(encodedCRL);
		CertificateFactory factory = CertificateFactory.getInstance("X.509");
		return (X509CRL) factory.generateCRL(bIn);
	}

	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchProviderException, SecurityException, SignatureException, CRLException, IllegalStateException, IllegalArgumentException, IOException, CertificateException {
		Security.addProvider(new BouncyCastleProvider());
		KeyPair caPair = RSA.generateKeys(1024);
		X509Certificate caCert = X509V1Certificate.generateV1Cert(caPair);
		KeyPair subjectPair = RSA.generateKeys(1024);
		PKCS10CertificationRequest certRequest = CertificateRequest.generateCertRequest(subjectPair);
		X509Certificate issuedCert = CertificateAuthority.generateCertFromCertRequest(certRequest, caCert, caPair.getPrivate());
		BigInteger sn = issuedCert.getSerialNumber();
		X509CRL crl = createCRL(caCert,caPair.getPrivate(), sn);
		crl.verify(caCert.getPublicKey());
		System.out.println("CRL Verified. ");
		X509CRLEntry entry = crl.getRevokedCertificate(sn);
		System.out.println(" Certificate number: " + entry.getSerialNumber());
		// reconstruct encoded certificate revocation list
		byte[] encodedCRL = crl.getEncoded();
		X509CRL reconstructedCRL = reconstructEncodedCRL(encodedCRL);
		System.out.println("original CRL and reconstructed CRL are equal : "+reconstructedCRL.equals(crl));
		
	}

}
