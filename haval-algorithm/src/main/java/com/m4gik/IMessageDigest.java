package com.m4gik;

/**
 * The basic visible methods of any hash algorithm.
 * <p>
 * A hash (or message digest) algorithm produces its output by iterating a basic
 * compression function on blocks of data.
 */
public interface IMessageDigest extends Cloneable {
    /**
     * Returns the algorithm's (inner) block size in bytes.
     * 
     * @return the algorithm's inner block size in bytes.
     */
    int blockSize();

    /**
     * Returns a clone copy of this instance.
     * 
     * @return a clone copy of this instance.
     */
    Object clone();

    /**
     * Completes the message digest by performing final operations such as
     * padding and resetting the instance.
     * 
     * @return the array of bytes representing the hash value.
     */
    byte[] digest();

    /**
     * Returns the output length in bytes of this message digest algorithm.
     * 
     * @return the output length in bytes of this message digest algorithm.
     */
    int hashSize();

    /**
     * Returns the canonical name of this algorithm.
     * 
     * @return the canonical name of this instance.
     */
    String name();

    /**
     * Resets the current context of this instance clearing any eventually
     * cached intermediary values.
     */
    void reset();

    /**
     * A basic test. Ensures that the digest of a pre-determined message is
     * equal to a known pre-computed value.
     * 
     * @return <code>true</code> if the implementation passes a basic self-test.
     *         Returns <code>false</code> otherwise.
     */
    boolean selfTest();

    /**
     * Continues a message digest operation using the input byte.
     * 
     * @param b
     *            the input byte to digest.
     */
    void update(byte b);

    /**
     * Continues a message digest operation, by filling the buffer, processing
     * data in the algorithm's HASH_SIZE-bit block(s), updating the context and
     * count, and buffering the remaining bytes in buffer for the next
     * operation.
     * 
     * @param in
     *            the input block.
     */
    void update(byte[] in);

    /**
     * Continues a message digest operation, by filling the buffer, processing
     * data in the algorithm's HASH_SIZE-bit block(s), updating the context and
     * count, and buffering the remaining bytes in buffer for the next
     * operation.
     * 
     * @param in
     *            the input block.
     * @param offset
     *            start of meaningful bytes in input block.
     * @param length
     *            number of bytes, in input block, to consider.
     */
    void update(byte[] in, int offset, int length);
}