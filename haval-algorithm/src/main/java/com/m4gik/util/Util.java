package com.m4gik.util;

/**
 * A collection of utility methods used throughout this project. This class
 * mainly contains method for implementing the operations of presenting data.
 * 
 * @author Michał Szczygieł <michal.szczygiel@wp.pl>
 * 
 */
public class Util {
    /**
     * Hex charset.
     */
    private static final char[] HEX_DIGITS = "0123456789ABCDEF".toCharArray();

    /**
     * This method checks if given string contains hex value.
     * 
     * @param hexValue
     *            the value to check if is hexadecimal representation.
     * @return the given hex value.
     * @throws Exception
     */
    private static String checkHexValue(String hexValue) {
        if (!hexValue.matches("\\A\\b[0-9a-fA-F]+\\b\\Z")) {
            throw new NumberFormatException(
                    "This value is not hexadecimal representation!");
        }

        return hexValue;
    }

    /**
     * Returns a string of hexadecimal digits from a byte array. Each byte is
     * converted to 2 hex symbols; zero(es) included.
     * <p>
     * This method calls the method with same name and three arguments as:
     * 
     * <pre>
     * toString(ba, 0, ba.length);
     * </pre>
     * 
     * @param ba
     *            the byte array to convert.
     * @return a string of hexadecimal characters (two for each byte)
     *         representing the designated input byte array.
     */
    public static String toString(byte[] ba) {
        return toString(ba, 0, ba.length);
    }

    /**
     * Returns a string of hexadecimal digits from a byte array, starting at
     * <code>offset</code> and consisting of <code>length</code> bytes. Each
     * byte is converted to 2 hex symbols; zero(es) included.
     * 
     * @param ba
     *            the byte array to convert.
     * @param offset
     *            the index from which to start considering the bytes to
     *            convert.
     * @param length
     *            the count of bytes, starting from the designated offset to
     *            convert.
     * @return a string of hexadecimal characters (two for each byte)
     *         representing the designated input byte sub-array.
     */
    public static final String toString(byte[] ba, int offset, int length) {
        char[] buf = new char[length * 2];
        for (int i = 0, j = 0, k; i < length;) {
            k = ba[offset + i++];
            buf[j++] = HEX_DIGITS[(k >>> 4) & 0x0F];
            buf[j++] = HEX_DIGITS[k & 0x0F];
        }
        return checkHexValue(new String(buf));
    }

    /**
     * Trivial constructor to enforce Singleton pattern.
     */
    private Util() {
        super();
    }

}
