package com.m4gik;

/**
 * 
 * This class contains static fields, attributes for {@link Haval} class.
 * 
 * @author Michał Szczygieł <michal.szczygiel@wp.pl>
 * 
 */
public class HavalAttributes {

    /**
     * The value specify the inner block size in bytes.
     */
    public static final int BLOCK_SIZE = 128;

    /**
     * The value for produce hashes in lengths of 128 bits.
     */
    public static final int HAVAL_128_BIT = 16;

    /**
     * The value for produce hashes in lengths of 160 bits.
     */
    public static final int HAVAL_160_BIT = 20;

    /**
     * The value for produce hashes in lengths of 192 bits.
     */
    public static final int HAVAL_192_BIT = 24;

    /**
     * The value for produce hashes in lengths of 224 bits.
     */
    public static final int HAVAL_224_BIT = 28;

    /**
     * The value for produce hashes in lengths of 256 bits.
     */
    public static final int HAVAL_256_BIT = 32;

    /**
     * The value specify the number of 3 rounds which are used to generate the
     * hash.
     */
    public static final int HAVAL_3_ROUND = 3;

    /**
     * The value specify the number of 4 rounds which are used to generate the
     * hash.
     */
    public static final int HAVAL_4_ROUND = 4;

    /**
     * The value specify the number of 5 rounds which are used to generate the
     * hash.
     */
    public static final int HAVAL_5_ROUND = 5;

    /**
     * Name for algorithm.
     */
    public static final String HAVAL_NAME = "haval";

    /**
     * The value specify the version of algorithm.
     */
    public static final int HAVAL_VERSION = 1;

    /**
     * Word processing orders for first pass.
     */
    public static final int[] WORD_PROCESING_ORDER_1 = { 0, 1, 2, 3, 4, 5, 6,
            7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31 };

    /**
     * Word processing orders for second pass.
     */
    public static final int[] WORD_PROCESING_ORDER_2 = { 5, 14, 26, 18, 11, 28,
            7, 16, 0, 23, 20, 22, 1, 10, 4, 8, 30, 3, 21, 9, 17, 24, 29, 6, 19,
            12, 15, 13, 2, 25, 31, 27 };

    /**
     * Word processing orders for third pass.
     */
    public static final int[] WORD_PROCESING_ORDER_3 = { 19, 9, 4, 20, 28, 17,
            8, 22, 29, 14, 25, 12, 24, 30, 16, 26, 31, 15, 7, 3, 1, 0, 18, 27,
            13, 6, 21, 10, 23, 11, 5, 2 };

    /**
     * Word processing orders for fourth pass.
     */
    public static final int[] WORD_PROCESING_ORDER_4 = { 24, 4, 0, 14, 2, 7,
            28, 23, 26, 6, 30, 20, 18, 25, 19, 3, 22, 11, 31, 21, 8, 27, 12, 9,
            1, 29, 5, 15, 17, 10, 16, 13 };

    /**
     * Word processing orders for fifth pass.
     */
    public static final int[] WORD_PROCESING_ORDER_5 = { 27, 3, 21, 26, 17, 11,
            20, 29, 19, 0, 12, 7, 13, 8, 31, 10, 5, 9, 14, 30, 18, 6, 28, 24,
            2, 23, 16, 22, 4, 1, 25, 15 };
}
