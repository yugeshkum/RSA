import java.io.*;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.*;

public class rsa_cl {
    static BigInteger N;
    static BigInteger e;

    private static String bytesToString(byte[] encrypted) {
        String test = "";
        for (byte b : encrypted) {
            test += Byte.toString(b);
        }
        return test;
    }

    public static byte[] encrypt(byte[] message) {
        return (new BigInteger(message)).modPow(e, N).toByteArray();
    }

    public static void main(String[] args) throws Exception {
        Socket sock = new Socket("127.0.0.1", 4000);
        System.out.println("Connected");

        // Getting the public key
        InputStream istream = sock.getInputStream();
        BufferedReader socketRead = new BufferedReader(new InputStreamReader(istream));

        String Nstr = socketRead.readLine();
        String estr = socketRead.readLine();

        // Convert Nstr and estr to BigInt
        N = new BigInteger(Nstr);
        e = new BigInteger(estr);

        // Read the message to encrypt
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        System.out.println("Enter the plain text:");
        String teststring = br.readLine();

        System.out.println("Encrypting String: " + teststring);
        System.out.println("Encrypting String in bytes: " + bytesToString(teststring.getBytes()));
        // encrypt the read message
        byte[] encrypted = encrypt(teststring.getBytes());
        System.out.println("Encrypted string to send in bytes: " + bytesToString(encrypted));

        // Defining to send the encrypted text
        OutputStream ostream = sock.getOutputStream();
        DataOutputStream dOut = new DataOutputStream(ostream);

        // Send encrypted text
        dOut.writeInt(encrypted.length); // write length of the message
        dOut.write(encrypted); // write the message
    }
}
