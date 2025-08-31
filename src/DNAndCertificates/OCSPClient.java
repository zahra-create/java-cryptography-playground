package DNAndCertificates;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Vector;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.CertID;
import org.bouncycastle.asn1.ocsp.OCSPRequest;
import org.bouncycastle.asn1.ocsp.Request;
import org.bouncycastle.asn1.ocsp.TBSRequest;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import asymmetric.encryption.RSA;

public class OCSPClient {
	
	public static CertID createCertId(X509Certificate issuerCert, BigInteger serialNumber) throws NoSuchAlgorithmException {
		// 1. hash algorithm identifier
		AlgorithmIdentifier hashAlgorithm = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
		// 2. Compute issuerNameHash: Hash of issuer's distinguished name
        byte[] issuerNameEncoded = issuerCert.getSubjectX500Principal().getEncoded();
        byte[] issuerNameHash = MessageDigest.getInstance("SHA-256").digest(issuerNameEncoded);
        DEROctetString issuerNameHashOctet = new DEROctetString(issuerNameHash);
        // 3. Compute issuerKeyHash: Hash of issuer's public key
        byte[] issuerPublicKeyEncoded = issuerCert.getPublicKey().getEncoded();
        byte[] issuerKeyHash = MessageDigest.getInstance("SHA-256").digest(issuerPublicKeyEncoded);
        DEROctetString issuerKeyHashOctet = new DEROctetString(issuerKeyHash);
        // 4. Create serial number
        ASN1Integer asnSerialNumber = new ASN1Integer(serialNumber);
        // 5. Create CertID
        return new CertID(hashAlgorithm, issuerNameHashOctet, issuerKeyHashOctet, asnSerialNumber);
	}
	public static TBSRequest createTBSRequest(CertID[] certIDs, X509Extensions extensions) {

		// 1. Create Request objects from CertIDs
		Request[] requests = new Request[certIDs.length];
		for (int i = 0; i < certIDs.length; i++) {
			requests[i] = new Request(certIDs[i], null); // null for no singleRequestExtensions
		}

		// 2. Convert Requests to ASN1Sequence
		ASN1Sequence requestList = new DERSequence(requests);

		// 3. Create TBSRequest
		return new TBSRequest(null, requestList, extensions); // null : no requestor name specified
}
	
	public static OCSPRequest generateOCSPRequest(X509Certificate issuerCert, BigInteger serialNumber) throws NoSuchAlgorithmException {
		CertID targetCertID = createCertId(issuerCert, serialNumber);
		CertID[] certIDs = new CertID[] {targetCertID};
		// nonce extension
		 BigInteger nonce = BigInteger.valueOf(System.currentTimeMillis());
		 Vector oids = new Vector();
		 Vector values = new Vector();
		 oids.add(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.1.2"));  // id-pkix-ocsp-nonce
		 values.add(new X509Extension(false, new DEROctetString(nonce.toByteArray())));
		 X509Extensions requestExtensions = new X509Extensions(oids,values);
		 TBSRequest tbsRequest = createTBSRequest(certIDs, requestExtensions);
		 return new OCSPRequest(tbsRequest,null);
	}
	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchProviderException, SecurityException, SignatureException, IOException, CertificateEncodingException, CertificateParsingException, IllegalArgumentException, IllegalStateException {
		Security.addProvider(new BouncyCastleProvider());
		//1. create certificates
		KeyPair issuerPair = RSA.generateKeys(1024);
		KeyPair serverPair = RSA.generateKeys(1024);
		X509Certificate issuerCert = X509V1Certificate.generateV1Cert(issuerPair);
		PKCS10CertificationRequest serverCertRequest = CertificateRequest.generateCertRequest(serverPair);
		X509Certificate serverCert = CertificateAuthority.generateCertFromCertRequest(serverCertRequest, issuerCert, issuerPair.getPrivate());
		//2. get server certificate serial number
		BigInteger serverSN = serverCert.getSerialNumber();
		//3. generate OCSPRequest
		OCSPRequest ocspReq = generateOCSPRequest(issuerCert, serverSN);
		System.out.println("OCSP request created successfully");
		
	
		 
		 

	}

}
