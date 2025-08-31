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
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLSelector;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;

import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import asymmetric.encryption.RSA;

public class CRLCertStore {

	public static CertStore createCRLCertStore(X509CRL crl) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
		CollectionCertStoreParameters params = new CollectionCertStoreParameters(Collections.singleton(crl));
		return  CertStore.getInstance("collection", params);
		
	}
	
	
	public static void main(String[] args) throws InvalidKeyException, CertificateEncodingException, CRLException, IllegalStateException, NoSuchAlgorithmException, SignatureException, InvalidAlgorithmParameterException, NoSuchProviderException, SecurityException, IOException, CertificateParsingException, IllegalArgumentException, CertStoreException {
		Security.addProvider(new BouncyCastleProvider());
		KeyPair caPair = RSA.generateKeys(1024);
		X509Certificate caCert = X509V1Certificate.generateV1Cert(caPair);
		KeyPair subjectPair = RSA.generateKeys(1024);
		PKCS10CertificationRequest certRequest = CertificateRequest.generateCertRequest(subjectPair);
		X509Certificate issuedCert = CertificateAuthority.generateCertFromCertRequest(certRequest, caCert, caPair.getPrivate());
		BigInteger sn = issuedCert.getSerialNumber();
		X509CRL crl = X509CRLCreation.createCRL(caCert,caPair.getPrivate(), sn);
		CertStore crlStore = createCRLCertStore(crl);
		X509CRLSelector selector = new X509CRLSelector();
		selector.addIssuer(crl.getIssuerX500Principal());
		Collection selectedCrls = crlStore.getCRLs(selector);
		Iterator it = selectedCrls.iterator();
		while (it.hasNext()) {
			X509CRL selectedCRL = (X509CRL)it.next();
			System.out.println("CRL Issuer : "+selectedCRL.getIssuerX500Principal());
		}

	}

}
