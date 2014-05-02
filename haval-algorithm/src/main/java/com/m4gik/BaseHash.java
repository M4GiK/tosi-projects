package com.m4gik;

/**
 * A base abstract class to facilitate hash implementations.
 * 
 * @author Michał Szczygieł <michal.szczygiel@wp.pl>
 */
public abstract class BaseHash implements IMessageDigest {
    /** The hash (inner) block size in bytes. */
    protected int blockSize;

    /** Temporary input buffer. */
    protected byte[] buffer;

    /** Number of bytes processed so far. */
    protected long count;

    /** The hash (output) size in bytes. */
    protected int hashSize;

    /** The canonical name prefix of the hash. */
    protected String name;

    /**
     * Trivial constructor for use by concrete subclasses.
     * 
     * @param name
     *            the canonical name prefix of this instance.
     * @param hashSize
     *            the block size of the output in bytes.
     * @param blockSize
     *            the block size of the internal transform.
     */
    protected BaseHash(String name, int hashSize, int blockSize) {
        super();

        checkName(name);
        checkHashSize(hashSize);

        this.name = name;
        this.hashSize = hashSize;
        this.blockSize = blockSize;
        this.buffer = new byte[blockSize];

        resetContext();
    }

    public int blockSize() {
        return blockSize;
    }

    /**
     * This method checks the given hash size.
     * 
     * @param hashSize
     *            The hash size to check.
     */
    private void checkHashSize(int hashSize) {
        if (hashSize <= 0) {
            throw new IllegalArgumentException(
                    "hashSize cannot less or equal to zero");
        }
    }

    /**
     * This method checks if the given name is proper.
     * 
     * @param name
     *            The name to check.
     */
    private void checkName(String name) {
        if (name == null || name.isEmpty()) {
            throw new IllegalArgumentException("name cannot be null or empty");
        }
    }

    public abstract Object clone();

    public byte[] digest() {
        byte[] tail = padBuffer(); // pad remaining bytes in buffer
        update(tail, 0, tail.length); // last transform of a message
        byte[] result = getResult(); // make a result out of context

        reset(); // reset this instance for future re-use

        return result;
    }

    /**
     * Constructs the result from the contents of the current context.
     * 
     * @return the output of the completed hash operation.
     */
    protected abstract byte[] getResult();

    public int hashSize() {
        checkHashSize(hashSize);
        return hashSize;
    }

    public String name() {
        checkName(this.name);
        return name;
    }

    /**
     * Returns the byte array to use as padding before completing a hash
     * operation.
     * 
     * @return the bytes to pad the remaining bytes in the buffer before
     *         completing a hash operation.
     */
    protected abstract byte[] padBuffer();

    public void reset() { // reset this instance for future re-use
        count = 0L;
        for (int i = 0; i < blockSize;) {
            buffer[i++] = 0;
        }

        resetContext();
    }

    /** Resets the instance for future re-use. */
    protected abstract void resetContext();

    /**
     * The block digest transformation per se.
     * 
     * @param in
     *            the <i>blockSize</i> long block, as an array of bytes to
     *            digest.
     * @param offset
     *            the index where the data to digest is located within the input
     *            buffer.
     */
    protected abstract void transform(byte[] in, int offset);

    public void update(byte b) {
        // compute number of bytes still unhashed; ie. present in buffer
        int i = (int) (count % blockSize);
        count++;
        buffer[i] = b;
        if (i == (blockSize - 1)) {
            transform(buffer, 0);
        }
    }

    public void update(byte[] b) {
        update(b, 0, b.length);
    }

    public void update(byte[] b, int offset, int len) {
        int n = (int) (count % blockSize);
        count += len;
        int partLen = blockSize - n;
        int i = 0;

        if (len >= partLen) {
            System.arraycopy(b, offset, buffer, n, partLen);
            transform(buffer, 0);
            for (i = partLen; i + blockSize - 1 < len; i += blockSize) {
                transform(b, offset + i);
            }

            n = 0;
        }

        if (i < len) {
            System.arraycopy(b, offset + i, buffer, n, len - i);
        }
    }
}