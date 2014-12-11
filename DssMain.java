package dssimplementation;

import java.io.*;
import java.math.*;
import java.security.SecureRandom;

public class DssMain {

    static SecureRandom rnd = new SecureRandom();

    public static void main(String[] args) {

        BigInteger p = null;
        BigInteger q = null;
        BigInteger g = null;
        BigInteger x;
        BigInteger y;
        String nextLine = "";
        int n;

        //Any of two readers:

        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));

//        BufferedReader reader = null;
//        try {
//            reader = new BufferedReader(new FileReader("verify"));
//        } catch (Exception e) {
//            System.out.println("Input file not found");
//            System.exit(0);
//        }

        //Import p,q,g
        for (int i = 0; i < 3; i++) {
            try {
                nextLine = reader.readLine();
            } catch (IOException ioe) {
                System.out.println("An unexpected error occured.");
            }
            if (i == 0) {
                p = new BigInteger(nextLine.substring(2));
            } else if (i == 1) {
                q = new BigInteger(nextLine.substring(2));
            } else {
                g = new BigInteger(nextLine.substring(2));
            }
        }
        DsaParameters param = new DsaParameters(p, q, g);
        boolean validParameters = checkParameters(param);
        if (validParameters) {
            System.out.println("valid_group");
            try {
                nextLine = reader.readLine();
            } catch (IOException ioe) {
                System.out.println("An unexpected error occured.");
            }
            switch (nextLine) {
                case "genkey":
                    genkey(reader, param);
                    break;
                case "sign":
                    sign(reader, param);
                    break;
                case "verify":
                    verify(reader, param);
                    break;
                default:
                    System.out.println("Unexpexted fourth input line.");
                    break;
            }
        } else {
            System.out.println("invalid_group");
        }
        System.exit(0);
    }

    public static boolean checkParameters(DsaParameters param) {
        BigInteger p = param.getP();
        BigInteger q = param.getQ();
        BigInteger g = param.getG();
        boolean pPrime = p.isProbablePrime(50); //40 is minimum number of iterations according to standard (p.69)
        boolean qPrime = q.isProbablePrime(50);
        boolean p1024 = (p.bitLength() == 1024);
        boolean q160 = (q.bitLength() == 160);
        boolean qDivP = (p.subtract(BigInteger.ONE).remainder(q).compareTo(BigInteger.ZERO) == 0);  //q divisor of p-1
        boolean gq1 = (g.modPow(q, p).compareTo(BigInteger.ONE)) == 0;                              //g^q mod p = 1
        boolean g1 = (g.compareTo(BigInteger.ONE) == 1);                                            //g>1
        boolean gp1 = (g.compareTo(p.subtract(BigInteger.ONE)) == -1);                              //g<p-1
        return (pPrime && qPrime && p1024 && q160 && qDivP && gq1 && g1 && gp1);
    }

    public static KeyPair generateKeys(DsaParameters param) {
        BigInteger g = param.getG();
        BigInteger p = param.getP();
        BigInteger q = param.getQ();

        BigInteger x;
        do {
            x = new BigInteger(q.bitLength(), rnd);
        } while (x.compareTo(q) >= 0 || x.compareTo(BigInteger.ZERO) <= 0); //need 0<x<q

        BigInteger y = g.modPow(x, p);
        return new KeyPair(x, y);
    }

    private static void genkey(BufferedReader reader, DsaParameters param) throws NumberFormatException {
        int n;
        BigInteger x;
        BigInteger y;
        String nextLine = null;
        try {
            nextLine = reader.readLine();
        } catch (IOException ioe) {
            System.out.println("An unexpected error occured.");
        }
        n = Integer.parseInt(nextLine.substring(2));
        KeyPair keys;
        for (int i = 0; i < n; i++) {
            keys = generateKeys(param);
            x = keys.getX();
            y = keys.getY();
            System.out.println("x=" + x + "\ny=" + y);
        }
    }

    private static void sign(BufferedReader reader, DsaParameters param) {
        BigInteger x = null;
        BigInteger y = null;
        String nextLine = null;
        BigInteger D = null;
        Signature signature;

        for (int i = 0; i < 2; i++) {
            try {
                nextLine = reader.readLine();
            } catch (IOException ioe) {
                System.out.println("An unexpected error occured.");
                System.exit(0);
            }
            switch (i) {
                case 0:
                    x = new BigInteger(nextLine.substring(2));
                    break;
                case 1:
                    y = new BigInteger(nextLine.substring(2));
                    break;
            }
        }
        KeyPair keys = new KeyPair(x, y);
        DsaUser alice = new DsaUser(param, keys, rnd);
        try {
            while ((nextLine = reader.readLine()) != null) {
                try {
                    D = new BigInteger(nextLine.substring(2), 16);
                } catch (NumberFormatException e) {
                    System.out.println("Wrong format on message digest");
                }
                signature = alice.sign(D);
                System.out.println("r=" + signature.getR() + "\ns=" + signature.getS());
            }
        } catch (IOException ioe) {
            System.out.println("Unexpected IO exception");
        }
    }

    private static void verify(BufferedReader reader, DsaParameters param) {
        String nextLine = null;
        BigInteger D = null;
        BigInteger r = null;
        BigInteger s;
        boolean valid;

        try {
            nextLine = reader.readLine();
        } catch (IOException ioe) {
            System.out.println("Unexpected reader error");
        }
        BigInteger y = new BigInteger(nextLine.substring(2));
        DsaUser bob = new DsaUser(param, new KeyPair(BigInteger.ZERO, y), rnd);

        int i = 0;
        try {
            while ((nextLine = reader.readLine()) != null) {
                switch (i) {
                    case 0:
                        try {
                            D = new BigInteger(nextLine.substring(2), 16);
                        } catch (NumberFormatException e) {
                            System.out.println("Wrong format on message digest");
                        }
                        break;
                    case 1:
                        r = new BigInteger(nextLine.substring(2));
                        break;
                    case 2:
                        s = new BigInteger(nextLine.substring(2));
                        valid = bob.verify(D, new Signature(r, s));
                        if (valid) {
                            System.out.println("signature_valid");
                        } else {
                            System.out.println("signature_invalid");
                        }
                        break;
                }
                i = (i + 1) % 3;
            }
        } catch (IOException ioe) {
            System.out.println("An unexpected error occured.");
            System.exit(0);
        }
    }

//    private static int computeT(double pT, int k) {  //Computes #rounds for MR primality testing s.t. p(false)<pT;
//        int t;
//        double p, mSum, jSum;
//        for (t = 1; t <= -Math.log(pT) / Math.log(2); t++) {
//            for (int M = 3; M <= 2 * Math.sqrt(k - 1) - 1; M++) {
//                mSum = 0;
//                for (int m = 3; m <= M; m++) {
//                    jSum = 0;
//                    for (int j = 2; j <= m; j++) {
//                        jSum = jSum + 1 / (Math.pow(2, j + (k - 1) / j));
//                    }
//                    mSum = mSum + Math.pow(2, m - (m - 1) * t) * jSum;
//                }
//                p = 2.00743 * Math.log(2) * k * Math.pow(2, -k) * (Math.pow(2, k - 2 - M * t) + 8 * (Math.pow(Math.PI, 2) - 6) / 3 * Math.pow(2, k - 1) * mSum);
//                if (p <= pT) {
//                    return t;
//                }
//            }
//        }
//        return t;
//    }
}
