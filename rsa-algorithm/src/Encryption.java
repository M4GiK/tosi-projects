import java.math.BigInteger;

/**
 * Project RSA Algorithm.
 * Copyright Michał Szczygieł.
 * Created at Feb 24, 2014.
 */

/**
 * This interface describe the basic operation with encryption algorithm.
 * 
 * @author Michał Szczygieł <michal.szczygiel@wp.pl>
 * 
 */
public interface Encryption {

    /**
     * This method makes operation to achieve decrypted message.
     * 
     * @param valueToDecrypt
     *            The value of which will be performed the decryption process.
     * @return Decrypted value.
     */
    public BigInteger decrypt(BigInteger valueToDecrypt);

    /**
     * This method makes operation to create encrypted message.
     * 
     * @param valueToEncrypt
     *            The value of which will be performed the encryption process
     * @return Encrypted value.
     */
    public BigInteger encrypt(BigInteger valueToEncrypt);

}
