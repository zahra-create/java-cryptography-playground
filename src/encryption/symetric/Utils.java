package encryption.symetric;

public class Utils {
	private static String digits = "0123456789abcdef";
	public static String toHex(byte[] data) {
		int dataLength = data.length;
		StringBuffer buffer = new StringBuffer();
		for (int i=0; i<dataLength; i++)
		{
			int p = data[i] & 0xff;
			buffer.append(digits.charAt(p >> 4));
			buffer.append(digits.charAt(p & 0xf));
			
		}
		return buffer.toString();	}

}
