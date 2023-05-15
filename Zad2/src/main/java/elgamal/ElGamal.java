package elgamal;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;

public class ElGamal {
    private BigInteger g;
    private BigInteger h;
    private BigInteger a;
    private BigInteger P;
    private BigInteger Pm1;
    private BigInteger r;
    private BigInteger rn1;
    private final MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
    private final int keyLength = 512;
    private final Random random = new SecureRandom();

    public ElGamal() throws NoSuchAlgorithmException {
        GenerujKlucz();
    }

    public BigInteger getG() {
        return g;
    }

    public BigInteger getH() {
        return h;
    }

    public BigInteger getA() {
        return a;
    }

    public BigInteger getP() {
        return P;
    }

    public BigInteger getPm1() {
        return Pm1;
    }

    public void GenerujKlucz() {
        P = BigInteger.probablePrime(keyLength + 2, random);
        a = new BigInteger(P.bitLength() - 1, random).mod(P.subtract(BigInteger.ONE)).add(BigInteger.ONE);
        g = new BigInteger(keyLength, random);
        h = g.modPow(a, P);
        Pm1 = P.subtract(BigInteger.ONE);
    }

    public BigInteger[] podpis(byte[] text) {
        messageDigest.update(text);
        BigInteger podpis = new BigInteger(1, messageDigest.digest());
        r = new BigInteger(P.bitLength() - 1, random).mod(P.subtract(BigInteger.ONE)).add(BigInteger.ONE);
        BigInteger[] wynik = new BigInteger[2];
        while(true) {
            if(r.gcd(Pm1).equals(BigInteger.ONE)) {
                break;
            }
            else {
                r = r.nextProbablePrime();
            }
        }
        rn1 = r.modInverse(Pm1);
        BigInteger s1 = g.modPow(r, P);
        BigInteger s2 = podpis.subtract(a.multiply(s1)).multiply(rn1).mod(Pm1);
        wynik[0] = s1;
        wynik[1] = s2;
        return wynik;
    }

    public static byte[] hexToBytes(String text) {
        StringBuilder padded = new StringBuilder(text);
        if (padded.length() % 2 != 0) {
            padded.insert(0, "0");
        }
        text = padded.toString();
        text = text.toUpperCase();
        int len = text.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(text.charAt(i), 16) << 4)
                    + Character.digit(text.charAt(i + 1), 16));
        }
        return data;
    }
    public boolean weryfikacja(byte[] publicText, BigInteger[] signature) {
        messageDigest.update(publicText);
        BigInteger hash = new BigInteger(1, messageDigest.digest());
        BigInteger wynik1 = g.modPow(hash, P);
        BigInteger wynik2 = h.modPow(signature[0], P).multiply(signature[0].modPow(signature[1], P)).mod(P);
        return wynik1.compareTo(wynik2) == 0;
    }
}