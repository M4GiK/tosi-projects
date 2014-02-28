/**
 * Project RSA Algorithm.
 * Copyright Michał Szczygieł.
 * Created at Feb 24, 2014.
 */

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * This class represents implementation of RSA encryption algorithm.
 * 
 * @author Michał Szczygieł <michal.szczygiel@wp.pl>
 * 
 */
public class RSA implements Encryption {

    /**
     * The constant base for the operation.
     */
    private static final Integer BASE = 27;

    /**
     * The default value for fragmentation data.
     */
    public static final Integer BLOCK_SIZE = 10;

    /**
     * The padding character, if block data is smaller then block size should be
     * filled by this value.
     */
    public static final Character PADDING = 'z' + 1;

    /**
     * Field keeps the value of the multiplication of numbers p and q.
     */
    private BigInteger n;

    /**
     * Field stores private key for RSA encryption algorithm.
     */
    private BigInteger privateKey;

    /**
     * Field stores public key for RSA encryption algorithm.
     */
    public BigInteger publicKey;

    /**
     * The constructor for {@link RSA}. This method create an instance that can
     * both encrypt and decrypt.
     * 
     * @param bits
     *            The bits size for RSA key.
     */
    public RSA(Integer bits) {
        SecureRandom r = new SecureRandom();

        BigInteger p = new BigInteger(bits, 100, r); // Large prime number
        BigInteger q = new BigInteger(bits, 100, r); // Large prime number
        BigInteger e = euler(p, q); // Field stores value of Euler operations
                                    // for p and q, where p and q are large
                                    // prime numbers.

        n = p.multiply(q);
        publicKey = new BigInteger(Integer.toString(r.nextInt()));

        while (e.gcd(publicKey).intValue() > 1) {
            publicKey = publicKey.add(BigInteger.ONE);
        }

        privateKey = publicKey.modInverse(e);
    }

    /**
     * This method makes operation to achieve decrypted message.
     * 
     * @param valueToDecrypt
     *            The value of which will be performed the decryption process.
     * @return Decrypted value.
     */
    public synchronized BigInteger decrypt(BigInteger valueToDecrypt) {
        return valueToDecrypt.modPow(privateKey, n);
    }

    /**
     * This method makes operation to achieve decrypted message.
     * 
     * @param messageToDecrypt
     *            The message of which will be performed the decryption process.
     * @return Decrypted message.
     */
    public synchronized String decrypt(String messageToDecrypt) {
        return new String((new BigInteger(messageToDecrypt)).modPow(privateKey,
                n).toByteArray());
    }

    /**
     * This method makes operation to create encrypted message.
     * 
     * @param valueToEncrypt
     *            The value of which will be performed the encryption process
     * @return Encrypted value.
     */
    public synchronized BigInteger encrypt(BigInteger valueToEncrypt) {
        return valueToEncrypt.modPow(publicKey, n);
    }

    /**
     * This method makes operation to create encrypted message.
     * 
     * @param messageToEncrypt
     *            The message of which will be performed the encryption process
     * @return Encrypted message.
     */
    public synchronized String encrypt(String messageToEncrypt) {
        return (new BigInteger(messageToEncrypt.getBytes())).modPow(publicKey,
                n).toString();
    }

    /**
     * Gets value of Euler for p and q, where p and q are large prime numbers.
     * 
     * @param p
     *            The large prime number.
     * @param q
     *            The large prime number.
     * @return The value of Euler operations for p and q.
     */
    private BigInteger euler(BigInteger p, BigInteger q) {
        return (p.subtract(BigInteger.ONE)).multiply((q
                .subtract(BigInteger.ONE)));
    }

    /**
     * This method calculates a numeric translation of the letter block.
     * 
     * @param text
     *            The text to calculate a numeric value.
     * @param blockSize
     *            The size of text block.
     * @return The calculated value for given text.
     */
    public Long translateToLong(String text, Integer blockSize) {
        Long result = 0L;

        for (int i = 0; i < blockSize; i++) {
            result += (text.charAt(i) - 'a') * (long) Math.pow(BASE, i);
        }

        return result;
    }

    /**
     * This method translate back from given number to block of characters.
     * 
     * @param number
     *            The number to translate.
     * @param blockSize
     *            The size of text block.
     * @return The translated number to string.
     */
    public String translateToString(Long number, Integer blockSize) {
        String result = "";

        for (int i = blockSize - 1; i >= 0; i--) {
            Character character = (char) ('a' + (number / Math.pow(BASE, i)));
            number -= (long) (number / Math.pow(BASE, i))
                    * (long) Math.pow(BASE, i);

            if (!character.equals(PADDING)) {
                result += character;
            }
        }

        return new StringBuffer(result).reverse().toString();
    }
}
