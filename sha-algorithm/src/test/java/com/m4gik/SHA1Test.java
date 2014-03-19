/**
 * Project SHA1 Algorithm.
 * Copyright Michał Szczygieł.
 * Created at Mar 14, 2014.
 */

package com.m4gik;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import java.security.spec.InvalidParameterSpecException;

import org.junit.Test;

/**
 * This class contains JUnit tests for class {@link SHA1}.
 * 
 * @author Michał Szczygieł <michal.szczygiel@wp.pl>
 * 
 */
public class SHA1Test {

    private static final String EXAMPLE_TEXT = "The quick brown fox jumps over the lazy dog";
    private static final String HASHED_EXAMPLE_TEXT = "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12";

    /**
     * This test method checks SHA1 algorithm for given string, which should be
     * correct with another algorithm based on SHA1.
     * 
     * @throws Exception
     */
    @Test
    public void checkCorrectnessOfSHA1() throws Exception {
        // when
        String result = SHA1.hash(EXAMPLE_TEXT);
        // then
        assertThat(result, is(equalTo(HASHED_EXAMPLE_TEXT)));
    }

    /**
     * This test method checks SHA1 algorithm for given string, and this method
     * shouldn't return exeption
     * 
     * @throws Exception
     */
    @Test(
            expected = InvalidParameterSpecException.class)
    public void dataShouldBeMultipleOf64() throws Exception {
        // when
        SHA1.checkData(EXAMPLE_TEXT.getBytes());
        // then ... throw new Exception
    }
}
