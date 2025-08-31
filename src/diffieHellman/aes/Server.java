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
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHPublicKeySpec;

public class Server extends DHAes {

	Server() throws Exception {
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
	public static void main(String[] args) throws Exception {
		
		System.out.println("Wainting for the client ...");
		
		ServerSocket ss = new ServerSocket(9709);
		Socket serverSoc = ss.accept();
		System.out.println("the client is connected ...");
		
		
		System.out.println("secret key exchanging  ...");
		
		Server server = new Server();
		// 1 - send public key to client 
		server.savePublicKeyToFile("serverPKfile");
		System.out.println("the server public key was saved to file.");
		server.sendFile(serverSoc, "serverPKfile");
		// 2 - recieve public key from client
		server.receiveFile(serverSoc,"ClientPKfile" );
		PublicKey clientPublicKey = loadPublicKeyFromFile("ClientPKfile");
		
        
		// calculate the shared key
        server.setaesKey(clientPublicKey);
        System.out.println("secret key exchanging finished");
        
     

	}

}
