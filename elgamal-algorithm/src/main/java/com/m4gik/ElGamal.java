/**
 * Project ElGamal Algorithm.
 * Copyright Michał Szczygieł.
 * Created at Mar 19, 2014.
 */
package com.m4gik;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Collection;
import java.util.LinkedList;
import java.util.Random;

import es.usc.citius.common.parallel.Parallel;

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
    private static final int KEY_LENGTH = 4; // 64

    /**
     * The separator which separates the given string from another.
     */
    private static final String SEPARATOR = "x";

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
     * The filed to keep value for future verification.
     */
    private BigInteger r;

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
     * This method gets iterable instance for given array.
     * 
     * @param splitOrginalMessage
     *            The message for wich will be collects indexes.
     * @return The iterable instance with indexes for given array.
     */
    private Iterable<Integer> getIndexes(String[] splitOrginalMessage) {
        LinkedList<Integer> indexes = new LinkedList<Integer>();
        Integer index = 0;

        for (String string : splitOrginalMessage) {
            indexes.add(index++);
        }

        return indexes;
    }

    /**
     * This method return value probably prime for k which is relative to p - 1.
     * 
     * @return The probably prime value relative to p - 1.
     */
    private BigInteger getProbablyPrime() {
        BigInteger k = new BigInteger(KEY_LENGTH, this.secureRandom);

        while ((this.p.subtract(BigInteger.ONE)).gcd(k).intValue() != 1) {
            k = new BigInteger(KEY_LENGTH, this.secureRandom);
        }

        return k;
    }

    /**
     * This method gets value for verification of sign.
     * 
     * @return the r
     */
    public BigInteger getValueToVerification() {
        return r;
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
     * This method sets value to after verification of sign.
     * 
     * @param r
     *            the r to set
     */
    public void setValueToVerification(BigInteger r) {
        this.r = r;
    }

    /**
     * This method signs the given message using ElGamal algorithm.
     * 
     * @param message
     *            The message to sign.
     * @return The signed message.
     */
    public String sign(String message) {
        String encryptedMessage = "";
        String split[] = message.split("(?!^)");
        BigInteger k = getProbablyPrime();
        setValueToVerification(this.alpha.modPow(k, this.p));

        for (String string : split) {
            encryptedMessage += signPart(Integer.parseInt(string, 16), k);
            encryptedMessage += SEPARATOR;
        }

        return encryptedMessage;
    }

    /**
     * This method sing the given part of message to avoid long verify.
     * 
     * @param partOfMessage
     *            The part of message to sign
     * @param k
     *            The value of k which is probably prime.
     * @return The part of encrypted and sign message.
     */
    private String signPart(Integer partOfMessage, BigInteger k) {
        BigInteger messageToEncrypt = new BigInteger(partOfMessage.toString());
        BigInteger encryptedMessage = (messageToEncrypt.subtract(this.secretKey
                .multiply(getValueToVerification()))).multiply(k
                .modInverse(this.p.subtract(BigInteger.ONE)));

        return encryptedMessage.toString();
    }

    /**
     * This method verifies sign.
     * 
     * @param encryptedMessage
     *            The message which was encrypted.
     * @param valueToVerification
     *            The value which allows to identify encrypted message with
     *            original.
     * @param orginalMessage
     *            The original context message to verify with encrypted.
     * @return True if encrypted message can be verified with original message,
     *         false if did not.
     */
    public Boolean verify(String encryptedMessage,
            final BigInteger valueToVerification, String orginalMessage) {
        Boolean isVeryfied = true;
        final String splitEncryptedMessage[] = encryptedMessage
                .split(SEPARATOR);
        final String splitOrginalMessage[] = orginalMessage.split("(?!^)");

        Iterable<Integer> indexes = getIndexes(splitOrginalMessage);

        Collection<Boolean> verifyCollection = Parallel.ForEach(indexes,
                new Parallel.F<Integer, Boolean>() {

                    public Boolean apply(Integer index) {
                        return verifyPart(Integer.parseInt(
                                splitOrginalMessage[index], 16), Integer
                                .parseInt(splitEncryptedMessage[index]),
                                valueToVerification);
                    }

                });

        for (Boolean isVerify : verifyCollection) {
            if (isVeryfied) {
                isVeryfied = isVerify;
            }
        }

        return isVeryfied;
    }

    /**
     * This method verify the part of message. This performance is to avoid long
     * verification.
     * 
     * @param orginalMessage
     *            The part of original message, to verify with part of encrypted
     *            message.
     * @param encryptedMessage
     *            The portion of encrypted message.
     * @param valueToVerification
     *            The value which allows to identify encrypted message with
     *            original.
     * @return True if part of encrypted message can be verified with part of
     *         original message, false if did not.
     */
    private Boolean verifyPart(Integer orginalMessage,
            Integer encryptedMessage, BigInteger valueToVerification) {
        Boolean isVeryfied = false;

        BigInteger left = this.alpha.pow(orginalMessage).mod(this.p);
        BigInteger right = ((publicKey.modPow(valueToVerification, this.p))
                .multiply(valueToVerification.modPow(new BigInteger(
                        encryptedMessage.toString()), this.p))).mod(this.p);

        if (left.equals(right)) {
            isVeryfied = true;
        }

        return isVeryfied;
    }

}
