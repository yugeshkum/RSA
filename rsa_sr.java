import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.util.Random;

public class rsa_sr {

	private static String bytesToString(byte[] encrypted) {
		String test = "";
		for (byte b : encrypted) {
			test += Byte.toString(b);
		}
		return test;
	}

	public static void main(String[] args) throws Exception {
		RSA rsa = new RSA();
		// Creating connection
		ServerSocket sersock = new ServerSocket(4000);
		System.out.println("Server ready for connection");
		Socket sock = sersock.accept();
		System.out.println("Connection is successfull");

		// Defining to send the key text
		OutputStream ostream = sock.getOutputStream();
		PrintWriter pw = new PrintWriter(ostream, true);

		// Sending the public key (N and e)
		pw.println(rsa.N.toString());
		pw.println(rsa.e.toString());

		// Reading the encrypted text
		DataInputStream dIn = new DataInputStream(sock.getInputStream());
		int length = dIn.readInt(); // read length of incoming message
		byte[] message = new byte[length];
		if (length > 0) {
			dIn.readFully(message, 0, message.length); // read the message
			System.out.println("Encrypted bytes recieved: " + bytesToString(message));
		}

		// Decrypted the message
		byte[] decrypted = rsa.decrypt(message);
		System.out.println("Decrypted Bytes: " + bytesToString(decrypted));
		System.out.println("Decrypted String: " + new String(decrypted));
	}
}

class RSA {
	private BigInteger p; // To allow large values
	private BigInteger q;
	public BigInteger N;
	private BigInteger phi;
	public BigInteger e;
	private BigInteger d;
	private int bitlength = 1024;
	// To create random integers create instance for Random class
	private Random r;

	public RSA() {
		r = new Random();
		// The java.math.BigInteger.probablePrime(int bitLength, Random rnd) returns a
		// positive BigInteger that is probably prime, with the specified bitLength.
		p = BigInteger.probablePrime(bitlength, r);
		q = BigInteger.probablePrime(bitlength, r);
		N = p.multiply(q);
		phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
		e = BigInteger.probablePrime(bitlength / 2, r);
		// To generate ‘e’ so that e lies between 1 and phi
		while (phi.gcd(e).compareTo(BigInteger.ONE) > 0 && e.compareTo(phi) < 0) {
			e = e.add(BigInteger.ONE);
		}
		// To generate d as e-1 mod phi
		d = e.modInverse(phi);
	}

	public byte[] decrypt(byte[] message) {
		return (new BigInteger(message)).modPow(d, N).toByteArray();
	}
}