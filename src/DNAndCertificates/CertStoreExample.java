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
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.CertStoreParameters;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import asymmetric.encryption.RSA;

public class CertStoreExample {
	public static CertStore createCertStore(X509Certificate[] chain) throws CertificateException, NoSuchProviderException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
		CollectionCertStoreParameters params = new CollectionCertStoreParameters(Arrays.asList(chain));
		return CertStore.getInstance("collection", params);
	}

	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchProviderException, SecurityException, SignatureException, IOException, IllegalArgumentException, IllegalStateException, CertificateException, CertStoreException {
		Security.addProvider(new BouncyCastleProvider());
		KeyPair rootPair = RSA.generateKeys(1024);
		X509Certificate rootCert = X509V1Certificate.generateV1Cert(rootPair);
		KeyPair subjectPair = RSA.generateKeys(1024);
		PKCS10CertificationRequest certRequest = CertificateRequest.generateCertRequest(subjectPair);
		X509Certificate issuedCert = CertificateAuthority.generateCertFromCertRequest(certRequest, rootCert, rootPair.getPrivate());
		X509Certificate[] chain = CertificatePath.buildChain(rootCert, issuedCert);
		// generate CertStore object
		CertStore certStore = createCertStore(chain);
		// create the selector
		X509CertSelector selector = new X509CertSelector();
		selector.setSubject(new X500Principal("CN=test Cert"));
		
		// get selected certificates
		Collection selectedCerts = certStore.getCertificates(selector);
		// print selected certificates in the console
		Iterator it = selectedCerts.iterator();
		while (it.hasNext()) {
			PemWriter pemWriter = new PemWriter(new OutputStreamWriter(System.out));
			pemWriter.writeObject(new PemObject("CERTIFICATE",((X509Certificate)it.next()).getEncoded()));
			pemWriter.close();
		}

	}

}
