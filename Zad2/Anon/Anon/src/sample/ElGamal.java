package sample;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;

public class ElGamal {
    private BigInteger g;
    private BigInteger h;
    private BigInteger a;
    private BigInteger N;
    private BigInteger Nn1;
    private BigInteger r;
    private BigInteger rn1;
    private final MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
    private final int keyLength = 2048;
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

    public BigInteger getN() {
        return N;
    }

    public BigInteger getNn1() {
        return Nn1;
    }

    public void GenerujKlucz() {
        N = BigInteger.probablePrime(keyLength + 2, random);
        a = new BigInteger(keyLength, random);
        g = new BigInteger(keyLength, random);
        h = g.modPow(a, N);
        Nn1 = N.subtract(BigInteger.ONE);
    }

    public BigInteger[] podpis(byte[] text) {
        messageDigest.update(text);
        BigInteger podpis = new BigInteger(1, messageDigest.digest());
        r = BigInteger.probablePrime(keyLength, random);
        BigInteger[] wynik = new BigInteger[2];
        while(true) {
            if(r.gcd(Nn1).equals(BigInteger.ONE)) {
                break;
            }
            else {
                r = r.nextProbablePrime();
            }
        }
        rn1 = r.modInverse(Nn1);
        BigInteger s1 = g.modPow(r, N);
        BigInteger s2 = podpis.subtract(a.multiply(s1)).multiply(rn1).mod(Nn1);
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
        BigInteger wynik1 = g.modPow(hash, N);
        BigInteger wynik2 = h.modPow(signature[0], N).multiply(signature[0].modPow(signature[1], N)).mod(N);
        return wynik1.compareTo(wynik2) == 0;
    }
}