package KeyAndCertManagement;

import java.security.KeyStore;
import java.security.Security;
import java.security.KeyStore.Entry;
import java.security.KeyStore.ProtectionParameter;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class JCEKSStoreBuilder {

	public static void main(String[] args) throws Exception{
		Security.addProvider(new BouncyCastleProvider());
		KeyStore store = KeyStoreNestedClasses.createKeyStore();
		KeyStore.Builder builder = KeyStore.Builder.newInstance(store, new KeyStore.PasswordProtection(KeyStoreNestedClasses.keypassword));
		// retrieve the keystore
		KeyStore retrievedStore = builder.getKeyStore();
		ProtectionParameter param = builder.getProtectionParameter("end");
		Entry endEntry = retrievedStore.getEntry("end", param);
		System.out.println("recovered entry : "+endEntry.getClass());

	}

}
