/**
 * Project ElGamal Algorithm.
 * Copyright Michał Szczygieł.
 * Created at Mar 19, 2014.
 */
package com.m4gik;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

/**
 * This class represents implementation of ElGamal algorithm. This class contain
 * operations to sign and verify documents.
 * 
 * @author Michał Szczygieł <michal.szczygiel@wp.pl>
 * 
 */
public class ElGamal {

    /**
     * The length for ElGamal key.
     */
    private static final int KEY_LENGTH = 64;

    /**
     * The object to code/decode public key.
     */
    private BigInteger alpha;

    /**
     * The filed to keep probable prime value.
     */
    private BigInteger p;

    /**
     * The variable keeping the public key.
     */
    private BigInteger publicKey;

    /**
     * The variable keeping the private key.
     */
    private BigInteger secretKey;

    /**
     * The random instance for generating secure random values.
     */
    private Random secureRandom = new SecureRandom();

    /**
     * The constructor for {@link ElGamal} class, which creates the instance.
     * 
     * @param secretKey
     *            The private key.
     */
    public ElGamal(String secretKey) {
        setPrivateKey(secretKey);
        generatePublicKey(this.secretKey);

    }

    /**
     * This method generates public key from private key.
     * 
     * @param secretKey
     */
    private void generatePublicKey(BigInteger secretKey) {
        this.p = BigInteger.probablePrime(KEY_LENGTH, this.secureRandom);
        this.alpha = new BigInteger(Integer.toString(secureRandom.nextInt()));
        this.publicKey = alpha.modPow(secretKey, p);
    }

    /**
     * This method sets the private key.
     * 
     * @param secretKey
     */
    private void setPrivateKey(String secretKey) {
        this.secretKey = new BigInteger(secretKey);
    }

    /**
     * 
     * @return
     */
    public BigInteger sign(String message) {
        BigInteger messageToEncrypt = new BigInteger(message, 16);
        BigInteger k = new BigInteger(KEY_LENGTH, this.secureRandom);

        while (this.p.subtract(BigInteger.ONE).gcd(k).intValue() != 1) {
            k = new BigInteger(KEY_LENGTH, this.secureRandom);
        }

        BigInteger r = this.alpha.modPow(k, this.p);
        BigInteger encryptedMessage = (messageToEncrypt.subtract(this.secretKey
                .multiply(r))).multiply(k.modInverse(this.p
                .subtract(BigInteger.ONE)));

        return encryptedMessage;
    }

    /**
     * 
     * @param object
     * @param bigInteger
     * @return
     */
    public Boolean verify(BigInteger bigInteger, Object object) {
        // TODO Auto-generated method stub
        return null;
    }

}
