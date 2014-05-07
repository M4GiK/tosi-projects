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

}
