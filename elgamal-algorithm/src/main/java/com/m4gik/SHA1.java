/**
 * Project SHA1 Algorithm.
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
        int[] h = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 };
        int[] k = { 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6 };

        checkData(paddedData);

        int passesReq = paddedData.length / 64;
        byte[] work = new byte[64];

        for (int passCntr = 0; passCntr < passesReq; passCntr++) {
            System.arraycopy(paddedData, 64 * passCntr, work, 0, 64);
            processTheBlock(work, h, k);
        }

        return intArrayToHexStr(h);
    }

    /**
     * This method converts integer array to hex string and adds leading zeros.
     * 
     * @param data
     *            The data to transform.
     * @return The hexadecimal value of given integer array.
     */
    private static String intArrayToHexStr(int[] data) {
        String output = "";
        String tempStr = "";

        for (int cnt : data) {
            tempStr = String.format("%8s", Integer.toHexString(cnt)).replace(
                    ' ', '0');
            output = output + tempStr;
        }

        return output;
    }

    /**
     * This method makes pre-processing. Appends the bit '1' to the message i.e.
     * by adding 0x80 if characters are 8 bits. append 0 ≤ k < 512 bits '0',
     * thus the resulting message length (in bits) is congruent to 448 (mod 512)
     * append ml, in a 64-bit big-endian integer. So now the message length is a
     * multiple of 512 bits.
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
     * This method convert a string to a sequence of 16-word blocks, stored as
     * an array.
     * 
     * @param work
     *            The array of 64 bytes.
     * @param h
     *            The array with temporary values.
     * @param k
     *            The array with values.
     */
    private static void processTheBlock(byte[] work, int[] h, int[] k) {
        int[] w = new int[80];
        int a, b, c, d, e, f = 0;
        int temp;

        for (int outer = 0; outer < 16; outer++) {

            temp = 0;

            for (int inner = 0; inner < 4; inner++) {
                temp = (work[outer * 4 + inner] & 0x000000FF) << (24 - inner * 8);
                w[outer] = w[outer] | temp;
            }
        }

        for (int j = 16; j < 80; j++) {
            w[j] = rotateLeft(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1);
        }

        a = h[0];
        b = h[1];
        c = h[2];
        d = h[3];
        e = h[4];

        for (int j = 0; j < 80; ++j) {

            if (j <= 19) {
                f = (b & c) | ((~b) & d);
            } else if (j <= 39) {
                f = b ^ c ^ d;
            } else if (j <= 59) {
                f = (b & c) | (b & d) | (c & d);
            } else if (j <= 79) {
                f = b ^ c ^ d;
            }

            temp = rotateLeft(a, 5) + f + e + k[j / 20] + w[j];
            e = d;
            d = c;
            c = rotateLeft(b, 30);
            b = a;
            a = temp;
        }

        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
        h[4] += e;
    }

    /**
     * The method moves bites to left side.
     * 
     * @param value
     *            The value to rotated.
     * @param bits
     *            The bits size.
     * @return The rotated value.
     */
    final static int rotateLeft(int value, int bits) {
        int q = (value << bits) | (value >>> (32 - bits));
        return q;
    }
}
