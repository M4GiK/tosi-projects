package com.m4gik;

import static com.m4gik.HavalAttributes.HAVAL_128_BIT;
import static com.m4gik.HavalAttributes.HAVAL_3_ROUND;
import static com.m4gik.HavalAttributes.HAVAL_HASH;

//import static com.m4gik.HavalAttributes.*;
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
     * Calls the constructor with two argument using {@link #HAVAL_128_BIT} as
     * the value for the output size (i.e. <code>128</code> bits, and
     * {@link #HAVAL_3_ROUND} for the value of number of rounds.
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
     * @param size
     *            the output size in bytes of this instance.
     * @param rounds
     *            the number of rounds to apply when transforming data.
     * @throws IllegalArgumentException
     *             if the designated output size is invalid, or if the number of
     *             rounds is invalid.
     * @see #HAVAL_128_BIT
     * @see #HAVAL_160_BIT
     * @see #HAVAL_192_BIT
     * @see #HAVAL_224_BIT
     * @see #HAVAL_256_BIT
     * @see #HAVAL_3_ROUND
     * @see #HAVAL_4_ROUND
     * @see #HAVAL_5_ROUND
     */
    public Haval(int size, int rounds) {
        super(HAVAL_HASH, size, HAVAL_128_BIT);
        // TODO Auto-generated constructor stub
    }

    protected Haval(String name, int hashSize, int blockSize) {
        super(name, hashSize, blockSize);
        // TODO Auto-generated constructor stub
    }

    @Override
    public Object clone() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    protected byte[] getResult() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    protected byte[] padBuffer() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    protected void resetContext() {
        // TODO Auto-generated method stub

    }

    @Override
    protected void transform(byte[] in, int offset) {
        // TODO Auto-generated method stub

    }

}
