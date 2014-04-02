package com.m4gik;
/**
 * Project RSA Algorithm.
 * Copyright Michał Szczygieł.
 * Created at Feb 24, 2014.
 */

import java.math.BigInteger;

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
     * This method makes operation to achieve decrypted message.
     * 
     * @param messageToDecrypt
     *            The message of which will be performed the decryption process.
     * @return Decrypted message.
     */
    public String decrypt(String messageToDecrypt);

    /**
     * This method makes operation to create encrypted message.
     * 
     * @param valueToEncrypt
     *            The value of which will be performed the encryption process
     * @return Encrypted value.
     */
    public BigInteger encrypt(BigInteger valueToEncrypt);

    /**
     * This method makes operation to create encrypted message.
     * 
     * @param messageToEncrypt
     *            The message of which will be performed the encryption process
     * @return Encrypted message.
     */
    public String encrypt(String messageToEncrypt);

}
