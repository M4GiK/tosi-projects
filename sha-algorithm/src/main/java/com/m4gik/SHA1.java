/**
 * Project RSA Algorithm.
 * Copyright Michał Szczygieł.
 * Created at Mar 16, 2014.
 */
package com.m4gik;

import java.security.spec.InvalidParameterSpecException;

/**
 * This class represents implementation of SHA1 algorithm. This class contain
 * operations to create hash, for given array of characters.
 * 
 * @author Michał Szczygieł <michal.szczygiel@wp.pl>
 * 
 */
public class SHA1 {

    /**
     * This method check if given block of bytes is modulo 64.
     * 
     * @param paddedData
     *            The data to checks.
     * @throws InvalidParameterSpecException
     */
    public static void checkData(byte[] paddedData)
            throws InvalidParameterSpecException {
        if (paddedData.length % 64 != 0) {
            throw new InvalidParameterSpecException();
        }
    }

    /**
     * This method makes hash for given string. This method convert a string to
     * a sequence of 16-word blocks, stored as an array. Append padding bits and
     * the length, as described in the SHA1 standard.
     * 
     * @param stringToHash
     *            The given string to generate hash for it.
     * @return The SHA1 hash of given string.
     * @throws InvalidParameterSpecException
     */
    public static String hash(String message)
            throws InvalidParameterSpecException {
        byte[] paddedData = padTheMessage(message.getBytes());
        int[] H = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 };
        int[] K = { 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6 };

        checkData(paddedData);

        int passesReq = paddedData.length / 64;
        byte[] work = new byte[64];

        for (int passCntr = 0; passCntr < passesReq; passCntr++) {
            System.arraycopy(paddedData, 64 * passCntr, work, 0, 64);
            processTheBlock(work, H, K);
        }

        return intArrayToHexStr(H);
    }

    /**
     * 
     * @param h
     * @return
     */
    private static String intArrayToHexStr(int[] h) {
        // TODO Auto-generated method stub
        return null;
    }

    /**
     * This method
     * 
     * @param data
     *            The bytes of message to pad.
     * @return Padded message.
     */
    private static byte[] padTheMessage(byte[] data) {
        int origLength = data.length;
        int tailLength = origLength % 64;
        int padLength = 0;

        if ((64 - tailLength >= 9)) {
            padLength = 64 - tailLength;
        } else {
            padLength = 128 - tailLength;
        }

        byte[] thePad = new byte[padLength];
        thePad[0] = (byte) 0x80;
        long lengthInBits = origLength * 8;

        for (int cnt = 0; cnt < 8; cnt++) {
            thePad[thePad.length - 1 - cnt] = (byte) ((lengthInBits >> (8 * cnt)) & 0x00000000000000FF);
        }

        byte[] output = new byte[origLength + padLength];

        System.arraycopy(data, 0, output, 0, origLength);
        System.arraycopy(thePad, 0, output, origLength, thePad.length);

        return output;
    }

    /**
     * 
     * @param work
     * @param h
     * @param k
     */
    private static void processTheBlock(byte[] work, int[] h, int[] k) {
        // TODO Auto-generated method stub

    }
}
