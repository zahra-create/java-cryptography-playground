package hashing.digest;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import encryption.symetric.Utils;

public class MGF1 {
	final static double MAX_MASK = Math.pow(2,32);
	private static MessageDigest digest;
	//constructor
	public MGF1(MessageDigest digest) {this.digest = digest;}
	// Integer to array of bytes converter
	public static void I2OSP(int n, byte[] b) {
		b[3] = (byte)(n<<0);
		b[2] = (byte)(n<<8);
		b[1] = (byte)(n<<16);
		b[0] = (byte)(n<<24);
			
		}
		
		
	
	// Mask Generation Function
	public static byte[] generateMask(byte[] seed, int maskLength) {
		int hashLength = digest.getDigestLength();
		if ((maskLength/hashLength)>MAX_MASK ) {
			throw new IllegalArgumentException("Mask length too large");
		}
		int c=0;
		byte[] counterBytes = new byte[4];
		byte[] mask = new byte[maskLength];
		while (c<(maskLength/hashLength)) {
			I2OSP(c, counterBytes);
			digest.update(seed);
			digest.update(counterBytes);
			System.arraycopy(digest.digest(), 0, mask, c*hashLength, hashLength);
			c++;
			}
		if ((c*hashLength)<maskLength) {
			I2OSP(c, counterBytes);
			digest.update(seed);
			digest.update(counterBytes);
			System.arraycopy(digest.digest(), 0, mask, c*hashLength, maskLength-c*hashLength);
		}
		return mask;
		
	}
	
	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException {
		MGF1 mgf1 = new MGF1(MessageDigest.getInstance("SHA-1"));
		byte[] source = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
		System.out.println(Utils.toHex(mgf1.generateMask(source, 20)));

	}

}
