package DNAndCertificates;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Set;

import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import asymmetric.encryption.RSA;

public class CertPathValidationn {

	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchProviderException, SecurityException, SignatureException, IOException, IllegalArgumentException, IllegalStateException, CRLException, CertificateException, CertPathValidatorException {
		Security.addProvider(new BouncyCastleProvider());
		KeyPair rootPair = RSA.generateKeys(1024);
		KeyPair interPair = RSA.generateKeys(1024);
		KeyPair endPair = RSA.generateKeys(1024);
		// generate certificates
		X509Certificate rootCert = X509V1Certificate.generateV1Cert(rootPair);
		PKCS10CertificationRequest interCertRequest = CertificateRequest.generateCertRequest(interPair);
		X509Certificate interCert = CertificateAuthority.generateCertFromCertRequest(interCertRequest, rootCert, rootPair.getPrivate());
		PKCS10CertificationRequest endCertRequest = CertificateRequest.generateCertRequest(endPair);
		X509Certificate endCert = CertificateAuthority.generateCertFromCertRequest(endCertRequest, interCert, interPair.getPrivate());
		// generate CRLS
		BigInteger serialNumber = BigInteger.valueOf(2);
		X509CRL rootCRL = X509CRLCreation.createCRL(rootCert, rootPair.getPrivate(), serialNumber);
		X509CRL interCRL = X509CRLCreation.createCRL(interCert, interPair.getPrivate(), serialNumber);
		X509CRL endCRL = X509CRLCreation.createCRL(endCert, endPair.getPrivate(), serialNumber);
		// create CertSteor to support validation
		List list = new ArrayList();
		list.add(rootCert);
		list.add(interCert);
		list.add(endCert);
		list.add(rootCRL);
		list.add(interCRL);
		list.add(endCRL);
		CollectionCertStoreParameters params = new CollectionCertStoreParameters(list);
		CertStore store = CertStore.getInstance(
		"Collection", params);
		//  create trust anchor to be used when performing validation
		Set trust = Collections.singleton(new TrustAnchor(rootCert, null)); //  root verifies *.example.com 
		// create CetPath
		CertificateFactory fact = CertificateFactory.getInstance("X.509");
		List certChain = new ArrayList();
		certChain.add(endCert);
		certChain.add(interCert);
		
		CertPath certPath = fact.generateCertPath(certChain);
		// Validation
		CertPathValidator validator = CertPathValidator.getInstance("PKIX", "BC");
		PKIXParameters param = new PKIXParameters(trust);
		param.addCertStore(store);
		param.setDate(new Date());
		CertPathValidatorResult result = validator.validate(certPath, param);
		System.out.println("certificate path validated");
	
	}

}
