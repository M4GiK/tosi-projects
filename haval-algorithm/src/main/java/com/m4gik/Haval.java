package com.m4gik;

import static com.m4gik.HavalAttributes.BLOCK_SIZE;
import static com.m4gik.HavalAttributes.HAVAL_128_BIT;
import static com.m4gik.HavalAttributes.HAVAL_160_BIT;
import static com.m4gik.HavalAttributes.HAVAL_192_BIT;
import static com.m4gik.HavalAttributes.HAVAL_224_BIT;
import static com.m4gik.HavalAttributes.HAVAL_256_BIT;
import static com.m4gik.HavalAttributes.HAVAL_3_ROUND;
import static com.m4gik.HavalAttributes.HAVAL_4_ROUND;
import static com.m4gik.HavalAttributes.HAVAL_5_ROUND;
import static com.m4gik.HavalAttributes.HAVAL_NAME;
import static com.m4gik.HavalAttributes.HAVAL_VERSION;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import javax.crypto.IllegalBlockSizeException;

import com.m4gik.util.Util;

/**
 * The Haval (One-Way Hashing Algorithm) message-digest algorithm is a variable
 * output length, with variable number of rounds. By default, this
 * implementation allows Haval to be used as a drop-in replacement for md5.
 * 
 * @author Michał Szczygieł <michal.szczygiel@wp.pl>
 * 
 */
public class Haval extends BaseHash {

    /**
     * Creates the {@link Haval} hash value for given input bytes with two
     * argument using {@link HavalAttributes.#HAVAL_128_BIT} as the value for
     * the output size (i.e. <code>128</code> bits, and {@link
     * HavalAttributes.#HAVAL_3_ROUND} for the value of number of rounds
     * 
     * @param input
     *            the value from which obtain the hash.
     * @return hash value for {@link Haval} algorithm.
     */
    public static String hash(byte[] input) {
        return hash(input, HAVAL_128_BIT, HAVAL_3_ROUND);
    }

    /**
     * Creates the {@link Haval} hash value for given input bytes with the
     * designated output size (in bytes). Valid output <code>size</code> values
     * are <code>16</code>, <code>20</code>, <code>24</code>, <code>28</code>
     * and <code>32</code>. Valid values for <code>rounds</code> are in the
     * range <code>3..5</code> inclusive.
     * 
     * @param input
     *            the value from which obtain the hash.
     * @param size
     *            the output size in bytes of this instance.
     * @param rounds
     *            the number of rounds to apply when transforming data.
     * @throws IllegalArgumentException
     *             if the designated output size is invalid, or if the number of
     *             rounds is invalid.
     * 
     * @see HavalAttributes.#HAVAL_128_BIT
     * @see HavalAttributes.#HAVAL_160_BIT
     * @see HavalAttributes.#HAVAL_192_BIT
     * @see HavalAttributes.#HAVAL_224_BIT
     * @see HavalAttributes.#HAVAL_256_BIT
     * @see HavalAttributes.#HAVAL_3_ROUND
     * @see HavalAttributes.#HAVAL_4_ROUND
     * @see HavalAttributes.#HAVAL_5_ROUND
     * 
     * @return hash value for {@link Haval} algorithm.
     */
    public static String hash(byte[] input, int size, int rounds) {
        return Util.toString(new Haval(input, size, rounds).digest())
                .toLowerCase();
    }

    /** 128-bit interim result. */
    private int h0, h1, h2, h3, h4, h5, h6, h7;

    /**
     * Fields keep amount of rounds. Default value is 3 rounds.
     */
    private int rounds = HAVAL_3_ROUND;

    /**
     * Calls the constructor with two argument using {@link
     * HavalAttributes.#HAVAL_128_BIT} as the value for the output size (i.e.
     * <code>128</code> bits, and {@link HavalAttributes.#HAVAL_3_ROUND} for the
     * value of number of rounds.
     */
    public Haval() {
        this(HAVAL_128_BIT, HAVAL_3_ROUND);
    }

    /**
     * Constructs a <code>Haval</code> instance with the designated output size
     * (in bytes). Valid output <code>size</code> values are <code>16</code>,
     * <code>20</code>, <code>24</code>, <code>28</code> and <code>32</code>.
     * Valid values for <code>rounds</code> are in the range <code>3..5</code>
     * inclusive.
     * 
     * @param input
     *            the value from which obtain the hash.
     * @param size
     *            the output size in bytes of this instance.
     * @param rounds
     *            the number of rounds to apply when transforming data.
     * @throws IllegalArgumentException
     *             if the designated output size is invalid, or if the number of
     *             rounds is invalid.
     * 
     *             * @see HavalAttributes.#HAVAL_128_BIT
     * @see HavalAttributes.#HAVAL_160_BIT
     * @see HavalAttributes.#HAVAL_192_BIT
     * @see HavalAttributes.#HAVAL_224_BIT
     * @see HavalAttributes.#HAVAL_256_BIT
     * @see HavalAttributes.#HAVAL_3_ROUND
     * @see HavalAttributes.#HAVAL_4_ROUND
     * @see HavalAttributes.#HAVAL_5_ROUND
     */
    public Haval(byte[] input, int size, int rounds) {
        super(HAVAL_NAME, size, BLOCK_SIZE);
        checkHavalInput(input);
        checkHavalOutputSize(size);
        checkHavalRounds(rounds);
        this.setRounds(rounds);
        this.update(input);
    }

    /**
     * Private constructor for cloning purposes.
     * 
     * @param originalInstance
     *            the instance to clone.
     */
    public Haval(Haval originalInstance) {
        this(originalInstance.hashSize(), originalInstance.getRounds());

        this.h0 = originalInstance.h0;
        this.h1 = originalInstance.h1;
        this.h2 = originalInstance.h2;
        this.h3 = originalInstance.h3;
        this.h4 = originalInstance.h4;
        this.h5 = originalInstance.h5;
        this.h6 = originalInstance.h6;
        this.h7 = originalInstance.h7;
        this.count = originalInstance.count;
        this.buffer = originalInstance.buffer.clone();
    }

    /**
     * Constructs a <code>Haval</code> instance with the designated output size
     * (in bytes). Valid output <code>size</code> values are <code>16</code>,
     * <code>20</code>, <code>24</code>, <code>28</code> and <code>32</code>.
     * Valid values for <code>rounds</code> are in the range <code>3..5</code>
     * inclusive.
     * 
     * @param size
     *            the output size in bytes of this instance.
     * @param rounds
     *            the number of rounds to apply when transforming data.
     * @throws IllegalArgumentException
     *             if the designated output size is invalid, or if the number of
     *             rounds is invalid.
     * @see HavalAttributes.#HAVAL_128_BIT
     * @see HavalAttributes.#HAVAL_160_BIT
     * @see HavalAttributes.#HAVAL_192_BIT
     * @see HavalAttributes.#HAVAL_224_BIT
     * @see HavalAttributes.#HAVAL_256_BIT
     * @see HavalAttributes.#HAVAL_3_ROUND
     * @see HavalAttributes.#HAVAL_4_ROUND
     * @see HavalAttributes.#HAVAL_5_ROUND
     */
    public Haval(int size, int rounds) {
        super(HAVAL_NAME, size, BLOCK_SIZE);
        checkHavalOutputSize(size);
        checkHavalRounds(rounds);
        this.setRounds(rounds);
    }

    /**
     * This method checks proper input value for {@link Haval} hashing.
     * 
     * @param input
     *            the value to check.
     * @throws IllegalArgumentException
     */
    private void checkHavalInput(byte[] input) throws IllegalArgumentException {
        if (input == null) {
            throw new IllegalArgumentException("Input cannot be null");
        }
    }

    /**
     * This method checks proper output size for {@link Haval} algorithm.
     * 
     * @param size
     *            the size to check.
     * @throws IllegalArgumentException
     */
    private void checkHavalOutputSize(int size) throws IllegalArgumentException {
        if (size != HAVAL_128_BIT && size != HAVAL_160_BIT
                && size != HAVAL_192_BIT && size != HAVAL_224_BIT
                && size != HAVAL_256_BIT) {
            throw new IllegalArgumentException("Invalid HAVAL output size");
        }
    }

    /**
     * This method checks proper amount of rounds.
     * 
     * @param rounds
     *            the amount of rounds to check.
     * @throws IllegalArgumentException
     */
    private void checkHavalRounds(int rounds) throws IllegalArgumentException {
        if (rounds != HAVAL_3_ROUND && rounds != HAVAL_4_ROUND
                && rounds != HAVAL_5_ROUND) {
            throw new IllegalArgumentException("Invalid HAVAL number of rounds");
        }

    }

    /**
     * This method checks proper size of padding with checking last 10 special
     * bytes.
     * 
     * @param padBuffer
     *            the padded message result.
     * @param padding
     *            the value for pad data.
     * @return
     */
    private byte[] checkPadBufferSize(byte[] padBuffer, int padding) {
        for (int i = 1; i > padding; i++) {
            if (padBuffer[i] != 0x00) {
                try {
                    throw new IllegalBlockSizeException(
                            "Padding is not filled correctly");
                } catch (IllegalBlockSizeException e) {
                    e.printStackTrace();
                }
            }
        }

        return padBuffer;
    }

    /**
     * Returns a clone copy of this instance. This method overrides an existing
     * method.
     * 
     * @see com.m4gik.BaseHash#clone()
     */
    @Override
    public Object clone() {
        return new Haval(this);
    }

    private int f1(int x6, int x5, int x4, int x3, int x2, int x1, int x0) {
        return x1 & (x0 ^ x4) ^ x2 & x5 ^ x3 & x6 ^ x0;
    }

    private int f2(int x6, int x5, int x4, int x3, int x2, int x1, int x0) {
        return x2 & (x1 & ~x3 ^ x4 & x5 ^ x6 ^ x0) ^ x4 & (x1 ^ x5) ^ x3 & x5
                ^ x0;
    }

    private int f3(int x6, int x5, int x4, int x3, int x2, int x1, int x0) {
        return x3 & (x1 & x2 ^ x6 ^ x0) ^ x1 & x4 ^ x2 & x5 ^ x0;
    }

    private int f4(int x6, int x5, int x4, int x3, int x2, int x1, int x0) {
        return x4 & (x5 & ~x2 ^ x3 & ~x6 ^ x1 ^ x6 ^ x0) ^ x3
                & (x1 & x2 ^ x5 ^ x6) ^ x2 & x6 ^ x0;
    }

    private int f5(int x6, int x5, int x4, int x3, int x2, int x1, int x0) {
        return x0 & (x1 & x2 & x3 ^ ~x5) ^ x1 & x4 ^ x2 & x5 ^ x3 & x6;
    }

    /**
     * Permutations phi_{i,j}, i=3,4,5, j=1,...,i.
     * 
     * rounds = 3: 6 5 4 3 2 1 0 | | | | | | | (replaced by) phi_{3,1}: 1 0 3 5
     * 6 2 4 phi_{3,2}: 4 2 1 0 5 3 6 phi_{3,3}: 6 1 2 3 4 5 0
     * 
     * rounds = 4: 6 5 4 3 2 1 0 | | | | | | | (replaced by) phi_{4,1}: 2 6 1 4
     * 5 3 0 phi_{4,2}: 3 5 2 0 1 6 4 phi_{4,3}: 1 4 3 6 0 2 5 phi_{4,4}: 6 4 0
     * 5 2 1 3
     * 
     * rounds = 5: 6 5 4 3 2 1 0 | | | | | | | (replaced by) phi_{5,1}: 3 4 1 0
     * 5 2 6 phi_{5,2}: 6 2 1 0 3 4 5 phi_{5,3}: 2 6 0 4 3 1 5 phi_{5,4}: 1 5 3
     * 2 0 4 6 phi_{5,5}: 2 5 0 6 4 3 1
     * 
     * @param collectionH
     *            the data for interim result.
     * @param w
     *            the extra value to add.
     * @return The value for first permutation.
     */
    private Integer FF1(List<Integer> collectionH, int w) {
        Integer t = 0;

        if (getRounds() == 3) {
            f1(collectionH.get(1), collectionH.get(0), collectionH.get(3),
                    collectionH.get(5), collectionH.get(6), collectionH.get(2),
                    collectionH.get(4));
        } else if (getRounds() == 4) {
            f1(collectionH.get(2), collectionH.get(6), collectionH.get(1),
                    collectionH.get(4), collectionH.get(5), collectionH.get(3),
                    collectionH.get(0));
        } else {
            f1(collectionH.get(3), collectionH.get(4), collectionH.get(1),
                    collectionH.get(0), collectionH.get(5), collectionH.get(2),
                    collectionH.get(6));
        }

        return (t >>> 7 | t << 25)
                + (collectionH.get(7) >>> 11 | collectionH.get(7) << 21) + w;
    }

    private void fifthPass(int[] xTable, List<Integer> collectionH,
            List<Integer> constatnts) {
        // TODO Auto-generated method stub

    }

    /**
     * This method makes first pass for haval transformation.
     * 
     * @param xTable
     *            the table with information for this algorithm.
     * @param collectionH
     *            the data for interim result.
     */
    private void firstPass(int[] xTable, List<Integer> collectionH) {
        int index = 0;
        setProperConfiguration(collectionH);

        for (int i = 0; i < 4; i++) {
            for (int j = collectionH.size() - 1; j >= 0; j--) {
                collectionH
                        .set(j, FF1(rotate(collectionH, 1), xTable[index++]));
            }
        }
    }

    private void fourthPass(int[] xTable, List<Integer> collectionH,
            List<Integer> constatnts) {
        // TODO Auto-generated method stub

    }

    @Override
    protected byte[] getResult() {
        // TODO Auto-generated method stub
        return "null".getBytes();
    }

    /**
     * This methods gets set number of rounds for {@link Haval} algorithm.
     * 
     * @return the rounds
     */
    public int getRounds() {
        return rounds;
    }

    /**
     * Returns the byte array to use as padding before completing a hash
     * operation. This method overrides an existing method. HAVAL also uses a
     * 10-bit field DGSTLENG to specify the required number of bits in a digest.
     * In addition HAVAL uses a 3-bit field PASS to specify the number of passes
     * each message block is processed, and another 3-bit field VERSION to
     * indicate the version number of HAVAL. The number of bits in a digest can
     * be 128, 160, 192, 224 and 256, while the number of passes can be 3, 4 and
     * 5. The current version number of HAVAL is 1. HAVAL pads a message by
     * appending a single bit 1 next to the most significant bit of the message,
     * followed by zero or more bit 0s until the length of the (new) message is
     * 944 modulo 1024. Then, HAVAL appends to the message the 3-bit field
     * VERSION, followed by the 3-bit field PASS, the 10-bit field DGSTLENG and
     * the 64-bit field MSGLENG.
     * 
     * 
     * @return the bytes to pad the remaining bytes in the buffer before
     *         completing a hash operation.
     * 
     * @see com.m4gik.BaseHash#padBuffer()
     */
    @Override
    protected byte[] padBuffer() {
        // Pad out to 118 mod 128. Other 10 bytes have special use.
        int n = (int) (count % BLOCK_SIZE);
        int padding = (n < 118) ? (118 - n) : (246 - n);
        byte[] result = new byte[padding + 10];
        result[0] = (byte) 0x01;

        // Save the version number (LSB 3), the number of rounds (3 bits in the
        // middle), the fingerprint length (MSB 2 bits and next byte) and the
        // number of bits in the unpadded message.
        int bl = hashSize() * 8;
        int sigByte = (bl & 0x03) << 6;
        sigByte |= (getRounds() & 0x07) << 3;
        sigByte |= HAVAL_VERSION & 0x07;
        result[padding++] = (byte) sigByte;
        result[padding++] = (byte) (bl >>> 2);

        // Save number of bits, casting the long to an array of 8 bytes
        long bits = count << 3;
        int j = 0;
        for (int i = padding; i < result.length; i++, j++) {
            result[i] = (byte) (bits >>> (j * 8));
        }

        return checkPadBufferSize(result, padding);
    }

    /**
     * Resets the instance for future re-use. This method overrides an existing
     * method.
     * 
     * @see com.m4gik.BaseHash#resetContext()
     */
    @Override
    protected void resetContext() {
        h0 = 0x243F6A88;
        h1 = 0x85A308D3;
        h2 = 0x13198A2E;
        h3 = 0x03707344;
        h4 = 0xA4093822;
        h5 = 0x299F31D0;
        h6 = 0x082EFA98;
        h7 = 0xEC4E6C89;
    }

    /**
     * Rotates the elements in the specified list by the specified distance.
     * After calling this method, the element at index i will be the element
     * previously at index (i - distance) mod list.size(), for all values of i
     * between 0 and list.size()-1, inclusive. (This method has no effect on the
     * size of the list.)
     * 
     * @param <T>
     * 
     * @param collection
     *            the array to rotate.
     * @param index
     *            the distance to rotate.
     */
    private <T> List<T> rotate(List<T> collection, int index) {
        Collections.rotate(collection, index);
        return collection;
    }

    private void secondPass(int[] xTable, List<Integer> collectionH,
            List<Integer> constatnts) {
        // TODO Auto-generated method stub

    }

    /**
     * This method sets collection in proper order.
     * 
     * @param collectionH
     *            the collection to configuration.
     */
    private void setProperConfiguration(List<Integer> collectionH) {
        rotate(collectionH, 6);
    }

    /**
     * This method sets number of rounds for {@link Haval} algorithm.
     * 
     * @param rounds
     *            the rounds to set
     */
    public void setRounds(int rounds) {
        this.rounds = rounds;
    }

    private void thirdPass(int[] xTable, List<Integer> collectionH,
            List<Integer> constatnts) {
        // TODO Auto-generated method stub

    }

    /**
     * The updating algorithm H processes a block in 3, 4 or 5 passes, which is
     * specified by the 3-bit field PASS in the last block. This method
     * overrides an existing method. The first 8 constant words correspond to
     * the first 256 bits of the fraction part of phi. The 32 constant words
     * used in Pass 2 correspond to the next 1024 bits of the fraction part of
     * phi, which is followed by the 32 constant words used by Pass 3, the 32
     * constant words used by Pass 4 and the 32 constant words used by Pass 5.
     * The 136 constant words are listed in the following in hexadecimal form.
     * They appear in the following order:
     * 
     * 243F6A88 85A308D3 13198A2E 03707344 A4093822 299F31D0 082EFA98 EC4E6C89
     * 452821E6 38D01377 BE5466CF 34E90C6C C0AC29B7 C97C50DD 3F84D5B5 B5470917
     * 9216D5D9 8979FB1B D1310BA6 98DFB5AC 2FFD72DB D01ADFB7 B8E1AFED 6A267E96
     * BA7C9045 F12C7F99 24A19947 B3916CF7 0801F2E2 858EFC16 636920D8 71574E69
     * A458FEA3 F4933D7E 0D95748F 728EB658 718BCD58 82154AEE 7B54A41D C25A59B5
     * 9C30D539 2AF26013 C5D1B023 286085F0 CA417918 B8DB38EF 8E79DCB0 603A180E
     * 6C9E0E8B B01E8A3E D71577C1 BD314B27 78AF2FDA 55605C60 E65525F3 AA55AB94
     * 57489862 63E81440 55CA396A 2AAB10B6 B4CC5C34 1141E8CE A15486AF 7C72E993
     * B3EE1411 636FBC2A 2BA9C55D 741831F6 CE5C3E16 9B87931E AFD6BA33 6C24CF5C
     * 7A325381 28958677 3B8F4898 6B4BB9AF C4BFE81B 66282193 61D809CC FB21A991
     * 487CAC60 5DEC8032 EF845D5D E98575B1 DC262302 EB651B88 23893E81 D396ACC5
     * 0F6D6FF3 83F44239 2E0B4482 A4842004 69C8F04A 9E1F9B5E 21C66842 F6E96C9A
     * 670C9C61 ABD388F0 6A51A0D2 D8542F68 960FA728 AB5133A3 6EEF0B6C 137A3BE4
     * BA3BF050 7EFB2A98 A1F1651D 39AF0176 66CA593E 82430E88 8CEE8619 456F9FB4
     * 7D84A5C3 3B8B5EBE E06F75D8 85C12073 401A449F 56C16AA6 4ED3AA62 363F7706
     * 1BFEDF72 429B023D 37D0D724 D00A1248 DB0FEAD3 49F1C09B 075372C9 80991B7B
     * 25D479D8 F6E8DEF7 E3FE501A B6794C3B 976CE0BD 04C006BA C1A94FB6 409F60C4
     * 
     * 
     * @see com.m4gik.BaseHash#transform(byte[], int)
     */
    @Override
    protected void transform(byte[] in, int offset) {
        List<Integer> collectionH = Arrays.asList(h0, h1, h2, h3, h4, h5, h6,
                h7);
        List<Integer> constatnts = Arrays.asList(0x452821E6, 0x38D01377,
                0xBE5466CF, 0x34E90C6C, 0xC0AC29B7, 0xC97C50DD, 0x3F84D5B5,
                0xB5470917, 0x9216D5D9, 0x8979FB1B, 0xD1310BA6, 0x98DFB5AC,
                0x2FFD72DB, 0xD01ADFB7, 0xB8E1AFED, 0x6A267E96, 0xBA7C9045,
                0xF12C7F99, 0x24A19947, 0xB3916CF7, 0x0801F2E2, 0x858EFC16,
                0x636920D8, 0x71574E69, 0xA458FEA3, 0xF4933D7E, 0x0D95748F,
                0x728EB658, 0x718BCD58, 0x82154AEE, 0x7B54A41D, 0xC25A59B5,
                0x9C30D539, 0x2AF26013, 0xC5D1B023, 0x286085F0, 0xCA417918,
                0xB8DB38EF, 0x8E79DCB0, 0x603A180E, 0x6C9E0E8B, 0xB01E8A3E,
                0xD71577C1, 0xBD314B27, 0x78AF2FDA, 0x55605C60, 0xE65525F3,
                0xAA55AB94, 0x57489862, 0x63E81440, 0x55CA396A, 0x2AAB10B6,
                0xB4CC5C34, 0x1141E8CE, 0xA15486AF, 0x7C72E993, 0xB3EE1411,
                0x636FBC2A, 0x2BA9C55D, 0x741831F6, 0xCE5C3E16, 0x9B87931E,
                0xAFD6BA33, 0x6C24CF5C, 0x7A325381, 0x28958677, 0x3B8F4898,
                0x6B4BB9AF, 0xC4BFE81B, 0x66282193, 0x61D809CC, 0xFB21A991,
                0x487CAC60, 0x5DEC8032, 0xEF845D5D, 0xE98575B1, 0xDC262302,
                0xEB651B88, 0x23893E81, 0xD396ACC5, 0x0F6D6FF3, 0x83F44239,
                0x2E0B4482, 0xA4842004, 0x69C8F04A, 0x9E1F9B5E, 0x21C66842,
                0xF6E96C9A, 0x670C9C61, 0xABD388F0, 0x6A51A0D2, 0xD8542F68,
                0x960FA728, 0xAB5133A3, 0x6EEF0B6C, 0x137A3BE4, 0xBA3BF050,
                0x7EFB2A98, 0xA1F1651D, 0x39AF0176, 0x66CA593E, 0x82430E88,
                0x8CEE8619, 0x456F9FB4, 0x7D84A5C3, 0x3B8B5EBE, 0xE06F75D8,
                0x85C12073, 0x401A449F, 0x56C16AA6, 0x4ED3AA62, 0x363F7706,
                0x1BFEDF72, 0x429B023D, 0x37D0D724, 0xD00A1248, 0xDB0FEAD3,
                0x49F1C09B, 0x075372C9, 0x80991B7B, 0x25D479D8, 0xF6E8DEF7,
                0xE3FE501A, 0xB6794C3B, 0x976CE0BD, 0x04C006BA, 0xC1A94FB6,
                0x409F60C4);

        int[] XTable = new int[32];

        for (int i = 0; i < 32; i++) {
            XTable[i] = (in[offset++] & 0xFF) | (in[offset++] & 0xFF) << 8
                    | (in[offset++] & 0xFF) << 16 | (in[offset++] & 0xFF) << 24;
        }

        firstPass(XTable, collectionH);
        secondPass(XTable, collectionH, constatnts);
        thirdPass(XTable, collectionH, constatnts);
        if (getRounds() >= 4) {
            fourthPass(XTable, collectionH, constatnts);
            if (getRounds() == 5) {
                fifthPass(XTable, collectionH, constatnts);
            }
        }

        h7 += collectionH.get(7);
        h6 += collectionH.get(6);
        h5 += collectionH.get(5);
        h4 += collectionH.get(4);
        h3 += collectionH.get(3);
        h2 += collectionH.get(2);
        h1 += collectionH.get(1);
        h0 += collectionH.get(0);
    }
}
