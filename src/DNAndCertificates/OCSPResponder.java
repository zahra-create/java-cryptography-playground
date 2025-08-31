package DNAndCertificates;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.ocsp.CertID;
import org.bouncycastle.asn1.ocsp.CertStatus;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPRequest;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.asn1.ocsp.Request;
import org.bouncycastle.asn1.ocsp.ResponseData;
import org.bouncycastle.asn1.ocsp.RevokedInfo;
import org.bouncycastle.asn1.ocsp.SingleResponse;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import asymmetric.encryption.RSA;

import org.bouncycastle.asn1.ocsp.ResponderID;
import org.bouncycastle.asn1.ocsp.ResponseBytes;
import org.bouncycastle.asn1.x500.X500Name;
import java.util.Date;
import java.util.Vector;

public class OCSPResponder {
	public static int getCertStatusFromCRL(CertID certID, X509CRL crl) throws Exception {
	    // 1. Get the serial number from CertID
	    BigInteger targetSerialNumber = certID.getSerialNumber().getValue();
	    
	    //2.  Iterate through all revoked certificates in the CRL
	    for (Object revokedObject : crl.getRevokedCertificates()) {
	        X509CRLEntry revokedEntry = (X509CRLEntry) revokedObject;
	        
	        // Check if the serial number matches
	        if (revokedEntry.getSerialNumber().equals(targetSerialNumber)) {
	            return 1; // Revoked - serial number found in CRL
	        }
	    }
	    
	    return 0; // Good 
	}
	public static byte[] signResponseData(byte[] responseData, PrivateKey responderKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		Signature signer = Signature.getInstance("SHA256WithRSA");
		signer.initSign(responderKey);
		signer.update(responseData);
		return signer.sign();
	}
	public static byte[] extractNonceFromReq(OCSPRequest ocspReq) throws IOException {
		Extension nonceExt = ocspReq.getTbsRequest().getRequestExtensions().getExtension(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.1.2"));
		return nonceExt.getExtnValue().getEncoded();
	}
	public static BasicOCSPResponse createBasicOCSPResponse(X509Certificate responderCert, PrivateKey responderKey, OCSPRequest ocspReq, int certStatus) throws Exception {
		  CertID certID = getCertID(ocspReq);
		  // 1. create SingleResponse 
		  ASN1GeneralizedTime thisUpdate = new ASN1GeneralizedTime(new Date());
		  ASN1GeneralizedTime nextUpdate = new ASN1GeneralizedTime(new Date(System.currentTimeMillis() + 3600000));
		  CertStatus status;
		  if (certStatus == 0) { 
		        status = new CertStatus();
		  } else if (certStatus == 1) { 
		        RevokedInfo revokedInfo = new RevokedInfo(null, null); // (revocation time, revocation reason) to work on later
		        status = new CertStatus(revokedInfo);
		  } else { 
		        status = new CertStatus(2, DERNull.INSTANCE); // refers to unknown status
		  }
		  SingleResponse singleResponse = new SingleResponse(certID, status, thisUpdate, nextUpdate, (X509Extensions)null);
		  
		  // 3. Create response data structure
		  // Nonce extension
		  byte[] nonce = extractNonceFromReq(ocspReq);
		  Vector oids = new Vector();
		  Vector values = new Vector();
		  oids.add(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.1.2"));  // id-pkix-ocsp-nonce
		  values.add(new X509Extension(false, new DEROctetString(nonce)));
		  X509Extensions responseExtensions = new X509Extensions(oids,values);
		  ResponderID responderId = new ResponderID(new X500Name(responderCert.getSubjectX500Principal().getName()));
		  ResponseData responseData = new  ResponseData(responderId, thisUpdate, new DERSequence(singleResponse), responseExtensions);
		  
		  // 4. sign respnose data
		  byte[] responseDataEncoded = responseData.getEncoded();
		  byte[] signedResData = signResponseData(responseDataEncoded, responderKey);
		  DERBitString signature = new DERBitString(signedResData);
		  // 5. create algorithm identifier object
		  AlgorithmIdentifier algID = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.113549.1.1.11")); // SHA256WithRSA OID
		  // 6. transform X509Certificate object to ASN1Sequence
		  byte[] certBytes = responderCert.getEncoded();
		  ASN1InputStream asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(certBytes));
		  ASN1Sequence certs = (ASN1Sequence) asn1InputStream.readObject();
		  // 7. return BasicOCSPResponse object
		  return new BasicOCSPResponse(responseData, algID, signature, certs);
		 	    
	}
	public static ResponseBytes convertToResponseBytes(BasicOCSPResponse basicOCSPResp) throws IOException {
		 byte[] basicResponseBytes = basicOCSPResp.getEncoded();
		 ASN1OctetString response = new DEROctetString(basicResponseBytes);
		 ASN1ObjectIdentifier responseType = OCSPObjectIdentifiers.id_pkix_ocsp_basic;
		 return new ResponseBytes(responseType, response);
	}
	public static CertID getCertID(OCSPRequest ocspRequest) {
		ASN1Sequence requestList = ocspRequest.getTbsRequest().getRequestList();
		Request request = Request.getInstance(requestList.getObjectAt(0));
		return request.getReqCert();
	}
	
	public static OCSPResponse generateOCSPResponse(OCSPRequest ocspRequest, X509CRL crl, X509Certificate responderCert, PrivateKey responderKey ) throws Exception {
		CertID certID = getCertID(ocspRequest);
		int certStatus = getCertStatusFromCRL(certID, crl);
		BasicOCSPResponse basicresponse = createBasicOCSPResponse(responderCert, responderKey,  ocspRequest,  certStatus);
		ResponseBytes respBytes = convertToResponseBytes(basicresponse);
		OCSPResponseStatus responseStatus = new OCSPResponseStatus(OCSPResponseStatus.SUCCESSFUL);
		return new OCSPResponse(responseStatus,respBytes );
		
	}
	
	

	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		//1. create certificates
		KeyPair issuerPair = RSA.generateKeys(1024);
		KeyPair serverPair = RSA.generateKeys(1024);
		KeyPair responderPair = RSA.generateKeys(1024);
		X509Certificate responderCert = X509V1Certificate.generateV1Cert(responderPair);
		X509Certificate issuerCert = X509V1Certificate.generateV1Cert(issuerPair);
		PKCS10CertificationRequest serverCertRequest = CertificateRequest.generateCertRequest(serverPair);
		X509Certificate serverCert = CertificateAuthority.generateCertFromCertRequest(serverCertRequest, issuerCert, issuerPair.getPrivate());
		//2. get server certificate serial number
		BigInteger serverSN = serverCert.getSerialNumber();
		//3. generate OCSPRequest
		OCSPRequest ocspReq = OCSPClient.generateOCSPRequest(issuerCert, serverSN);
		// create crl
		X509CRL crl = X509CRLCreation.createCRL(issuerCert, issuerPair.getPrivate(), BigInteger.valueOf(2));
		//generate OCSPResponse
		generateOCSPResponse(ocspReq, crl, responderCert, responderPair.getPrivate());
		System.out.println("OCSP response created successfully");
		
				
				

	}

}
