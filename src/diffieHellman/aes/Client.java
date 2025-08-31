package diffieHellman.aes;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHPublicKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class Client extends DHAes{

	Client() throws Exception {
		super();
		// TODO Auto-generated constructor stub
	}
	
	public static void send(Socket socket,String str) throws Exception {
        OutputStream os = socket.getOutputStream();
        PrintWriter pw = new PrintWriter(os, true);
        // send the string
        pw.println(str);
		
	}
	
	public static String recieve(Socket socket) throws Exception {
		InputStream is = socket.getInputStream();
        BufferedReader br = new BufferedReader(new InputStreamReader(is));
        //return the recieved string
        return br.readLine();
   }
	
	public void savePublicKeyToFile(String filename) throws Exception {
	    DHPublicKey publicKey = (DHPublicKey)this.keyPair.getPublic();
	    
	    // Store both the public value (y) and parameters (p,g)
	    try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(filename))) {
	        oos.writeObject(publicKey.getY());
	        oos.writeObject(publicKey.getParams().getP());
	        oos.writeObject(publicKey.getParams().getG());
	    }
	}
	public static void sendFile(Socket socket, String filePath) throws IOException {
	    try (OutputStream os = socket.getOutputStream();
	         FileInputStream fis = new FileInputStream(filePath)) {
	        byte[] buffer = new byte[4096];
	        int bytesRead;
	        while ((bytesRead = fis.read(buffer)) != -1) {
	            os.write(buffer, 0, bytesRead);
	        }
	    }
	}
	
	public static PublicKey loadPublicKeyFromFile(String filename) throws Exception {
	    try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(filename))) {
	        BigInteger y = (BigInteger)ois.readObject();
	        BigInteger p = (BigInteger)ois.readObject();
	        BigInteger g = (BigInteger)ois.readObject();
	        
	        DHPublicKeySpec spec = new DHPublicKeySpec(y, p, g);
	        return KeyFactory.getInstance("DH").generatePublic(spec);
	    }
	}
	
	public static void receiveFile(Socket socket, String filePath) throws IOException {
	    try (InputStream is = socket.getInputStream();
	         FileOutputStream fos = new FileOutputStream(filePath)) {
	        byte[] buffer = new byte[4096];
	        int bytesRead;
	        while ((bytesRead = is.read(buffer)) != -1) {
	            fos.write(buffer, 0, bytesRead);
	        }
	    }
	}
	
	
        

	public static void main(String[] args) throws Exception {
		System.out.println("client is starting connection ...");
		
		Socket clientSoc = new Socket("localhost",9709);
		
		
		System.out.println("secret key exchanging  ...");
		Client client = new Client(); 
		// 1 - recieve public key from server 
		client.receiveFile(clientSoc,"serverPKfile" );
		PublicKey serverPublicKey = loadPublicKeyFromFile("serverPKfile");
		// 2 - send public key to server
		client.savePublicKeyToFile("ClientPKfile");
		System.out.println("the client public key was saved to file.");
		client.sendFile(clientSoc, "ClientPKfile");
		
		// calculate the shared key
        client.setaesKey(serverPublicKey);
		
		
		

	}

}
