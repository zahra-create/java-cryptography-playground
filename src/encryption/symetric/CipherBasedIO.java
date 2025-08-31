package encryption.symetric;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

public class CipherBasedIO {

	public static void encryptFile(String filePath, String encryptedFilePath, Key secretKey, IvParameterSpec iv) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException {
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
		
	
		FileInputStream input = new FileInputStream(filePath);
		FileOutputStream out = new FileOutputStream(encryptedFilePath);
		CipherOutputStream coutput = new CipherOutputStream(out, cipher);
		
		
		byte[] buffer = new byte[1024];
		int readBytes;
		while ((readBytes=input.read(buffer))!=-1) { coutput.write(buffer, 0, readBytes);}
		coutput.close();		
	}
	public static void decryptFile(String encryptedFile, String decryptedFile, Key secretkey, IvParameterSpec iv) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException {
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, secretkey, iv);
		
		FileInputStream input = new FileInputStream(encryptedFile);
		CipherInputStream cinput = new CipherInputStream(input, cipher);
	
		FileOutputStream out = new FileOutputStream(decryptedFile);
		
		
		byte[] buffer = new byte[1024];
		int readBytes;
		while((readBytes = cinput.read(buffer))!= -1) {
			out.write(buffer, 0, readBytes);
			
		}
		
	}
	
	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IOException {
		Key secretkey = RandomSecretKey.generateRandomKey(128);
		IvParameterSpec iv = AESCBC.generateRandomIV();
		encryptFile("file", "encryptedFile", secretkey, iv);
		decryptFile("encryptedFile", "decryptedFile", secretkey, iv);

	}

}
