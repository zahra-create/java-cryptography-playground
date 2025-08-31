package DNAndCertificates;

import java.io.IOException;
import java.io.OutputStreamWriter;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.util.Vector;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;


import asymmetric.encryption.RSA;

public class CertificateRequest {
// certification requests are always self signed, this ensure the request is done by the public key owner
	public static PKCS10CertificationRequest generateCertRequest(KeyPair pair) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, IOException {
		GeneralNames subjectAltNames = new GeneralNames(new GeneralName(GeneralName.rfc822Name,"test@test.com")); // GeneralName.rfc822Name means it is email address name
		Vector oids = new Vector();
		Vector values = new Vector();
		
		oids.add(X509Extensions.SubjectAlternativeName);
		values.add(new X509Extension(false, new DEROctetString(subjectAltNames)));
		X509Extensions extensions = new X509Extensions(oids,values);
		Attribute attribute = new Attribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest,new DERSet(extensions));
		return new PKCS10CertificationRequest("SHA256WithRSA", new X509Principal("CN=test Cert"), pair.getPublic(), new DERSet(attribute), pair.getPrivate());
	}
	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchProviderException, SignatureException, IOException {
		Security.addProvider(new BouncyCastleProvider());
		KeyPair pair = RSA.generateKeys(1024);
		PKCS10CertificationRequest certRequest = generateCertRequest(pair);
		PemWriter pemWriter = new PemWriter(new OutputStreamWriter(System.out));
		pemWriter.writeObject(new PemObject("CERTIFICATE REQUEST", certRequest.getEncoded()));
		pemWriter.close();
		

	}

}
