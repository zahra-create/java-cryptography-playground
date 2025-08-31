package DNAndCertificates;

import java.io.IOException;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Enumeration;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.crypto.signers.DSAKCalculator;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;
import org.bouncycastle.x509.extension.X509ExtensionUtil;

import asymmetric.encryption.RSA;

public class CertificateAuthority {

	public static X509Certificate generateCertFromCertRequest(PKCS10CertificationRequest certRequest, X509Certificate rootCert, PrivateKey rootPrivateKey) throws IOException, InvalidKeyException, IllegalArgumentException, NoSuchAlgorithmException, NoSuchProviderException, CertificateEncodingException, IllegalStateException, SignatureException, CertificateParsingException {
		X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
		certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
		certGen.setIssuerDN(rootCert.getSubjectX500Principal());
		certGen.setNotBefore(new Date(System.currentTimeMillis()));
		certGen.setNotAfter(new Date(System.currentTimeMillis()+50000));
		certGen.setSubjectDN(new X500Principal((certRequest.getCertificationRequestInfo().getSubject()).getEncoded()));
		certGen.setPublicKey(certRequest.getPublicKey());
		certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");
		// get extensions from certificate request
		ASN1Set attributes = certRequest.getCertificationRequestInfo().getAttributes();
		for (int i=0; i<attributes.size();i++) {
			Attribute attribute = Attribute.getInstance(attributes.getObjectAt(i));
			if (attribute.getAttrType().equals(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest)) {
				X509Extensions extensions = X509Extensions.getInstance(attribute.getAttrValues().getObjectAt(0));
				Enumeration e = extensions.oids();
				while (e.hasMoreElements()) {
					ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)e.nextElement();
					X509Extension ext = extensions.getExtension(oid);
					certGen.addExtension(oid, ext.isCritical(), ext.getValue().getOctets());
				}
			}
		}
		// add AuthorityKeyIdentifier extension : helps to identify the authority that signed the certificate (rootCert in this case) 
		certGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(rootCert) );
		// add basic constraints extension
		certGen.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(true));
		// Add Subject Key Identifier extension ...
		PublicKey subjectKey = certRequest.getPublicKey();
		SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(subjectKey.getEncoded());
		byte[] publicKeyBytes = spki.getPublicKeyData().getBytes();
		MessageDigest digest = MessageDigest.getInstance("SHA-1");
		byte[] keyIdentifier = digest.digest(publicKeyBytes);
		certGen.addExtension(X509Extensions.SubjectKeyIdentifier, false, new SubjectKeyIdentifier(keyIdentifier) );
		return certGen.generate(rootPrivateKey);
		
	}
	public static void main(String[] args) throws InvalidKeyException, NoSuchProviderException, SecurityException, SignatureException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, IOException, CertificateEncodingException, IllegalArgumentException, IllegalStateException, CertificateParsingException {
		Security.addProvider(new BouncyCastleProvider());
		KeyPair rootPair = RSA.generateKeys(1024);
		X509Certificate rootCert = X509V1Certificate.generateV1Cert(rootPair);
		KeyPair subjectPair = RSA.generateKeys(1024);
		PKCS10CertificationRequest certRequest = CertificateRequest.generateCertRequest(subjectPair);
		X509Certificate issuedCert = generateCertFromCertRequest(certRequest, rootCert, rootPair.getPrivate());
		PemWriter pemWriter = new PemWriter(new OutputStreamWriter(System.out));
		pemWriter.writeObject(new PemObject("CERTIFICATE", issuedCert.getEncoded()));
		pemWriter.close();

	}

}
