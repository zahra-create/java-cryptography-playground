package DNAndCertificates;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import asymmetric.encryption.RSA;

public class ReadAndWriteCerts {

	
	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchProviderException, SecurityException, SignatureException, IOException, CertificateException {
		Security.addProvider(new BouncyCastleProvider());
		KeyPair pair = RSA.generateKeys(512);
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		out.write(X509V1Certificate.generateV1Cert(pair).getEncoded());
		out.write(X509V3Certificate.generateV3cert(pair).getEncoded());
		out.close();
		ByteArrayInputStream in = new ByteArrayInputStream(out.toByteArray());
		CertificateFactory factory = CertificateFactory.getInstance("X.509","BC");
		Collection collection = new ArrayList();
		X509Certificate cert;
		while((cert=(X509Certificate)factory.generateCertificate(in))!=null) {
			collection.add(cert);
		}
		Iterator it = collection.iterator();
		while(it.hasNext()) {
			System.out.println("version : "+((X509Certificate)it.next()).getVersion());
		}

	}

}
