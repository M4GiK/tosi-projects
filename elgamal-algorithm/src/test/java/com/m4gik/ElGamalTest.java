/**
 * Project ElGamal Algorithm.
 * Copyright Michał Szczygieł.
 * Created at Mar 17, 2014.
 */

package com.m4gik;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import org.junit.Test;

/**
 * 
 * This class contains JUnit tests for class {@link ElGamal}.
 * 
 * @author Michał Szczygieł <michal.szczygiel@wp.pl>
 * 
 */
public class ElGamalTest {

    private static final String EXAMPLE_TEXT = "The quick brown fox jumps over the lazy dog";

    private static final String SECRET_KEY = "12345678901234567890";

    /**
     * This test method checks if ElGamal algorithm proper sign the document.
     * 
     * @throws Exception
     */
    @Test
    public void isSigned() throws Exception {
        // given
        ElGamal elGamal = new ElGamal(SECRET_KEY);
        // when
        Boolean isSigned = elGamal.sign(EXAMPLE_TEXT);
        // then
        assertThat(isSigned, is(equalTo(true)));
    }

    /**
     * This test method checks if ElGamal algorithm can verify own sign of
     * document.
     * 
     * @throws Exception
     */
    @Test
    public void isVerfied() throws Exception {
        // given
        ElGamal elGamal = new ElGamal(SECRET_KEY);
        // when
        Boolean isVerified = false;

        if (elGamal.sign(SHA1.hash(EXAMPLE_TEXT))) {
            isVerified = elGamal.verify();
        }

        // then
        assertThat(isVerified, is(equalTo(true)));
    }
}
