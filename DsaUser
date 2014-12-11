/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package dssimplementation;

import java.math.BigInteger;
import java.util.*;
import java.security.SecureRandom;

/**
 *
 * @author Harald
 */
public class DsaUser {

    private DsaParameters param_;
    private KeyPair keys_;
    private SecureRandom rnd_;

    public DsaUser(DsaParameters param, KeyPair keys, SecureRandom rnd) {
        param_ = param;
        keys_ = keys;
        rnd_ = rnd;
        
    }

    public Signature sign(BigInteger m) {
        BigInteger q = param_.getQ();
        BigInteger g = param_.getG();
        BigInteger p = param_.getP();
        BigInteger x = keys_.getX();
        BigInteger y = keys_.getY();

        BigInteger r = null;
        BigInteger s = null;
        BigInteger k;
        BigInteger kInv;
        BigInteger z;
        do {
            do {
                do {
                    k = new BigInteger(q.bitLength(), rnd_);
                } while (k.compareTo(q) >= 0 || k.compareTo(BigInteger.ZERO) <= 0); //need 0<k<q
                kInv = k.modInverse(q);
                r = (g.modPow(k, p)).mod(q);
            } while (r.compareTo(BigInteger.ZERO) <= 0);
            s = (kInv.multiply(m.add(x.multiply(r)))).mod(q);                  //s=kInv(z+xr) mod q, z=m as m is aready 160 bits.
        } while (s.compareTo(BigInteger.ZERO) <= 0);
        return new Signature(r, s);
    }

    public boolean verify(BigInteger D, Signature sign) {
        boolean valid = false;
        BigInteger r = sign.getR();
        BigInteger s = sign.getS();
        BigInteger q = param_.getQ();
        BigInteger p = param_.getP();
        BigInteger g = param_.getG();
        BigInteger y = keys_.getY();

        boolean r0 = r.compareTo(BigInteger.ZERO) > 0;
        boolean s0 = s.compareTo(BigInteger.ZERO) > 0;
        boolean rq = r.compareTo(q) < 0;
        boolean sq = s.compareTo(q) < 0;
        
        if (r0 && s0 && rq && sq) {
            BigInteger w = s.modInverse(q);
            BigInteger u1 = (D.multiply(w)).mod(q); //u1=Dw mod q
            BigInteger u2 = (r.multiply(w)).mod(q); //u2=rw mod q
            BigInteger v = ((g.modPow(u1, p)).multiply(y.modPow(u2, p))).mod(p).mod(q); //v=((g^u1)(y^u2))mod p mod q
            valid = (v.compareTo(r)==0);
        }
        return valid;
    }
}
