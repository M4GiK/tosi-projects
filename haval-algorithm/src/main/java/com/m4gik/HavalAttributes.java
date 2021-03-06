package com.m4gik;

import java.util.Arrays;
import java.util.List;

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
     * The static 136 constant words for haval transformation.
     */
    public static final List<Integer> CONSTANTS = Arrays.asList(0x452821E6,
            0x38D01377, 0xBE5466CF, 0x34E90C6C, 0xC0AC29B7, 0xC97C50DD,
            0x3F84D5B5, 0xB5470917, 0x9216D5D9, 0x8979FB1B, 0xD1310BA6,
            0x98DFB5AC, 0x2FFD72DB, 0xD01ADFB7, 0xB8E1AFED, 0x6A267E96,
            0xBA7C9045, 0xF12C7F99, 0x24A19947, 0xB3916CF7, 0x0801F2E2,
            0x858EFC16, 0x636920D8, 0x71574E69, 0xA458FEA3, 0xF4933D7E,
            0x0D95748F, 0x728EB658, 0x718BCD58, 0x82154AEE, 0x7B54A41D,
            0xC25A59B5, 0x9C30D539, 0x2AF26013, 0xC5D1B023, 0x286085F0,
            0xCA417918, 0xB8DB38EF, 0x8E79DCB0, 0x603A180E, 0x6C9E0E8B,
            0xB01E8A3E, 0xD71577C1, 0xBD314B27, 0x78AF2FDA, 0x55605C60,
            0xE65525F3, 0xAA55AB94, 0x57489862, 0x63E81440, 0x55CA396A,
            0x2AAB10B6, 0xB4CC5C34, 0x1141E8CE, 0xA15486AF, 0x7C72E993,
            0xB3EE1411, 0x636FBC2A, 0x2BA9C55D, 0x741831F6, 0xCE5C3E16,
            0x9B87931E, 0xAFD6BA33, 0x6C24CF5C, 0x7A325381, 0x28958677,
            0x3B8F4898, 0x6B4BB9AF, 0xC4BFE81B, 0x66282193, 0x61D809CC,
            0xFB21A991, 0x487CAC60, 0x5DEC8032, 0xEF845D5D, 0xE98575B1,
            0xDC262302, 0xEB651B88, 0x23893E81, 0xD396ACC5, 0x0F6D6FF3,
            0x83F44239, 0x2E0B4482, 0xA4842004, 0x69C8F04A, 0x9E1F9B5E,
            0x21C66842, 0xF6E96C9A, 0x670C9C61, 0xABD388F0, 0x6A51A0D2,
            0xD8542F68, 0x960FA728, 0xAB5133A3, 0x6EEF0B6C, 0x137A3BE4,
            0xBA3BF050, 0x7EFB2A98, 0xA1F1651D, 0x39AF0176, 0x66CA593E,
            0x82430E88, 0x8CEE8619, 0x456F9FB4, 0x7D84A5C3, 0x3B8B5EBE,
            0xE06F75D8, 0x85C12073, 0x401A449F, 0x56C16AA6, 0x4ED3AA62,
            0x363F7706, 0x1BFEDF72, 0x429B023D, 0x37D0D724, 0xD00A1248,
            0xDB0FEAD3, 0x49F1C09B, 0x075372C9, 0x80991B7B, 0x25D479D8,
            0xF6E8DEF7, 0xE3FE501A, 0xB6794C3B, 0x976CE0BD, 0x04C006BA,
            0xC1A94FB6, 0x409F60C4);

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
     * Proper order for get index of reverse collection of h elements.
     */
    public static final int INDEX_0 = 7;

    /**
     * Proper order for get index of reverse collection of h elements.
     */
    public static final int INDEX_1 = 6;

    /**
     * Proper order for get index of reverse collection of h elements.
     */
    public static final int INDEX_2 = 5;

    /**
     * Proper order for get index of reverse collection of h elements.
     */
    public static final int INDEX_3 = 4;

    /**
     * Proper order for get index of reverse collection of h elements.
     */
    public static final int INDEX_4 = 3;
    /**
     * Proper order for get index of reverse collection of h elements.
     */
    public static final int INDEX_5 = 2;

    /**
     * Proper order for get index of reverse collection of h elements.
     */
    public static final int INDEX_6 = 1;

    /**
     * Proper order for get index of reverse collection of h elements.
     */
    public static final int INDEX_7 = 0;

    /**
     * Word processing orders for first pass.
     */
    public static final int[] WORD_PROCESSING_ORDER_1 = { 0, 1, 2, 3, 4, 5, 6,
            7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31 };

    /**
     * Word processing orders for second pass.
     */
    public static final int[] WORD_PROCESSING_ORDER_2 = { 5, 14, 26, 18, 11,
            28, 7, 16, 0, 23, 20, 22, 1, 10, 4, 8, 30, 3, 21, 9, 17, 24, 29, 6,
            19, 12, 15, 13, 2, 25, 31, 27 };

    /**
     * Word processing orders for third pass.
     */
    public static final int[] WORD_PROCESSING_ORDER_3 = { 19, 9, 4, 20, 28, 17,
            8, 22, 29, 14, 25, 12, 24, 30, 16, 26, 31, 15, 7, 3, 1, 0, 18, 27,
            13, 6, 21, 10, 23, 11, 5, 2 };

    /**
     * Word processing orders for fourth pass.
     */
    public static final int[] WORD_PROCESSING_ORDER_4 = { 24, 4, 0, 14, 2, 7,
            28, 23, 26, 6, 30, 20, 18, 25, 19, 3, 22, 11, 31, 21, 8, 27, 12, 9,
            1, 29, 5, 15, 17, 10, 16, 13 };

    /**
     * Word processing orders for fifth pass.
     */
    public static final int[] WORD_PROCESSING_ORDER_5 = { 27, 3, 21, 26, 17,
            11, 20, 29, 19, 0, 12, 7, 13, 8, 31, 10, 5, 9, 14, 30, 18, 6, 28,
            24, 2, 23, 16, 22, 4, 1, 25, 15 };
}
