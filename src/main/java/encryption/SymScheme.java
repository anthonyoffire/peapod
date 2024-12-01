package encryption;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class SymScheme implements Serializable{
    private static final long serialVersionUID = 6000L;
    private final String algorithm = "AES/CBC/PKCS5Padding";
    private int bitlen;
    private byte[] iv;

    public SymScheme(int bitlen){
        iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        this.bitlen = bitlen;
    }

    public BigInteger encrypt(BigInteger plaintext, BigInteger key){
        Key ckey = new SecretKeySpec(key.toByteArray(), "AES");
        Cipher cipher;
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        try {
            cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.ENCRYPT_MODE, ckey, ivSpec);
            byte[] cipherBytes = cipher.doFinal(plaintext.toByteArray());
            return new BigInteger(cipherBytes);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException | NoSuchPaddingException e) {
            System.err.println("Failed to encrypt with AES");
            e.printStackTrace();
            System.exit(1);
        } 
        return null;
    }
    public BigInteger decrypt(BigInteger ciphertext, BigInteger key){
        Key ckey = new SecretKeySpec(key.toByteArray(), "AES");
        Cipher cipher;
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        try {
            cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.DECRYPT_MODE, ckey, ivSpec);
            byte[] plainBytes = cipher.doFinal(ciphertext.toByteArray());
            return new BigInteger(plainBytes);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException | NoSuchPaddingException e) {
            System.err.println("Failed to decrypt with AES");
            e.printStackTrace();
            System.exit(1);
        } 
        return null;
    }
    public int getBitLen(){
        return bitlen;
    }
}
