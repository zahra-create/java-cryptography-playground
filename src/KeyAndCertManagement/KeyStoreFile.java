package KeyAndCertManagement;

import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class KeyStoreFile {

	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		char[] storepass = "storepassword".toCharArray();
		// create jks keystore
		KeyStore store = KeyStoreExample.createKeyStore("JKS");
		store.store(new FileOutputStream("keystore.jks"), storepass);
		// create pkcs12 keystore
		store = KeyStoreExample.createKeyStore("PKCS12");
		store.store(new FileOutputStream("keystore.p12"), storepass);
		

	}

}
