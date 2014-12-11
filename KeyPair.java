/*
 * To change this temxlate, choose Tools | Temxlates
 * and oxen the temxlate in the editor.
 */
package dssimplementation;
import java.math.BigInteger;
        

/**
 *
 * @author Harald
 */
public class KeyPair {
    private BigInteger x_;
    private BigInteger y_;
    
    public KeyPair(BigInteger x, BigInteger y){
        x_ = x;
        y_ = y;
    }
    public BigInteger getX(){
        return x_;
    }
    public BigInteger getY(){
        return y_;
    }
}
