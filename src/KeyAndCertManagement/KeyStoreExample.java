package KeyAndCertManagement;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.cert.Certificate;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import javax.security.auth.x500.X500PrivateCredential;

import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import DNAndCertificates.CertificateAuthority;
import DNAndCertificates.CertificateRequest;
import DNAndCertificates.X509V1Certificate;
import asymmetric.encryption.RSA;

public class KeyStoreExample {
	public static String ROOT_ALIAS = "root";
	public static String INTERMEDIATE_ALIAS = "intermediate";
	public static String END_ENTITY_ALIAS = "end";
	public static X500PrivateCredential createRootCredential() throws Exception {
		KeyPair rootPair = RSA.generateKeys(1024);
		X509Certificate rootCert = X509V1Certificate.generateV1Cert(rootPair);
		return new X500PrivateCredential(rootCert, rootPair.getPrivate(), ROOT_ALIAS);
	}
	public static X500PrivateCredential createIntermediateCredential(PrivateKey caKey, X509Certificate caCert) throws Exception {
		KeyPair interPair = RSA.generateKeys(1024);
		PKCS10CertificationRequest interCertRequest = CertificateRequest.generateCertRequest(interPair);
		X509Certificate interCert = CertificateAuthority.generateCertFromCertRequest(interCertRequest, caCert, caKey);
		return new X500PrivateCredential(interCert, interPair.getPrivate(), INTERMEDIATE_ALIAS);	
	}
	public static X500PrivateCredential createEndCredential(PrivateKey interKey, X509Certificate interCert) throws Exception {
		KeyPair endPair = RSA.generateKeys(1024);
		PKCS10CertificationRequest endCertRequest = CertificateRequest.generateCertRequest(endPair);
		X509Certificate endCert = CertificateAuthority.generateCertFromCertRequest(endCertRequest, interCert, interKey);
		return new X500PrivateCredential(endCert, endPair.getPrivate(), END_ENTITY_ALIAS);	
	}
	
	public static KeyStore createKeyStore(String keystoreType) throws Exception {
		char[] keypassword = "keypassword".toCharArray();
		KeyStore store = KeyStore.getInstance(keystoreType);
		store.load(null,null); //load(file,password)
		X500PrivateCredential rootCredential = createRootCredential();
		X500PrivateCredential interCredential = createIntermediateCredential(rootCredential.getPrivateKey(), rootCredential.getCertificate());
		X500PrivateCredential endCredential = createEndCredential(interCredential.getPrivateKey(), interCredential.getCertificate());
		
		// set trusted certificate
		store.setCertificateEntry(rootCredential.getAlias(), rootCredential.getCertificate());
		// set end entity private key
		Certificate[] chain = new Certificate[3];
		chain[0] = endCredential.getCertificate();
		chain[1] = interCredential.getCertificate();
		chain[2] = rootCredential.getCertificate();
		store.setKeyEntry(endCredential.getAlias(), endCredential.getPrivateKey(), keypassword, chain);
		
		return store;
		
	}

	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		KeyStore store = createKeyStore("JKS");
		char[] storepassword = "storepassword".toCharArray();
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		// save the store
		store.store(out, storepassword);
		// reload from scratch 
		KeyStore reloadedStore = KeyStore.getInstance("JKS");
		reloadedStore.load(new ByteArrayInputStream(out.toByteArray()), storepassword);
		// 
		Enumeration en = reloadedStore.aliases();
		while(en.hasMoreElements()) {
			String alias = (String) en.nextElement();
			System.out.println("the alias "+alias+" is certificate :"+store.isCertificateEntry(alias));
		}

	}

}
