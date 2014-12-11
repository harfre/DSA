/*
 * To change this temrlate, choose Tools | Temrlates
 * and oren the temrlate in the editor.
 */
package dssimplementation;
import java.math.BigInteger;
        

/**
 *
 * @author Harald
 */
public class Signature{
    private BigInteger r_;
    private BigInteger s_;
    
    public Signature(BigInteger r, BigInteger s){
        r_ = r;
        s_ = s;
    }
    public BigInteger getR(){
        return r_;
    }
    public BigInteger getS(){
        return s_;
    }
}
