package KeyAndCertManagement;

import java.security.KeyStore;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.Enumeration;

import javax.crypto.SecretKey;
import javax.security.auth.x500.X500PrivateCredential;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import encryption.symetric.AESCBC;

public class KeyStoreNestedClasses {
	/*
	 * in this class we will use JCEKS instead of JKS because we want to store secret key too but JKS doesn't support secret key storage
	 */
	
	public static char[] keypassword = "keypassword".toCharArray();
	
	public static KeyStore createKeyStore() throws Exception {
		KeyStore store = KeyStore.getInstance("JCEKS");
		store.load(null,null);
		X500PrivateCredential rootCredential = KeyStoreExample.createRootCredential();
		X500PrivateCredential interCredential = KeyStoreExample.createIntermediateCredential(rootCredential.getPrivateKey(), rootCredential.getCertificate());
		X500PrivateCredential endCredential = KeyStoreExample.createEndCredential(interCredential.getPrivateKey(), interCredential.getCertificate());
		SecretKey secretKey = AESCBC.generateKey(256);
		// set root certificate entry
		store.setEntry(rootCredential.getAlias(), new KeyStore.TrustedCertificateEntry(rootCredential.getCertificate()), null);
		// set secret key entry
		store.setEntry("secretKey", new KeyStore.SecretKeyEntry(secretKey), new KeyStore.PasswordProtection(keypassword));
		// set private key entry
		Certificate[] chain = new Certificate[] {endCredential.getCertificate(), interCredential.getCertificate(), rootCredential.getCertificate()};
		store.setEntry(endCredential.getAlias(), new KeyStore.PrivateKeyEntry(endCredential.getPrivateKey(), chain), new KeyStore.PasswordProtection(keypassword));
		
		return store;
	}

	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		KeyStore store = createKeyStore();
		Enumeration en = store.aliases();
		while (en.hasMoreElements()) {
			String alias = (String) en.nextElement();
			if (store.isCertificateEntry(alias)) System.out.println(alias+" is certificate entry");
			else if (store.entryInstanceOf(alias, KeyStore.SecretKeyEntry.class)) System.out.println(alias+" is secret key entry");
			else System.out.println(alias+" is private key entry");
		}

	}

}
