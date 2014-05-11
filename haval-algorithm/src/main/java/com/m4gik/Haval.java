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
     * This method sets number of rounds for {@link Haval} algorithm.
     * 
     * @param rounds
     *            the rounds to set
     */
    public void setRounds(int rounds) {
        this.rounds = rounds;
    }

    @Override
    protected void transform(byte[] in, int offset) {
        // TODO Auto-generated method stub

    }

}
