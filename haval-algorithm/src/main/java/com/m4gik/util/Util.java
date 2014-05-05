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
     * Base-64 chars.
     */
    private static final String BASE64_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz./";

    /**
     * Base-64 charset.
     */
    private static final char[] BASE64_CHARSET = BASE64_CHARS.toCharArray();

    /**
     * Hex charset.
     */
    private static final char[] HEX_DIGITS = "0123456789ABCDEF".toCharArray();

    /**
     * Trivial constructor to enforce Singleton pattern.
     */
    private Util() {
        super();
    }

}
