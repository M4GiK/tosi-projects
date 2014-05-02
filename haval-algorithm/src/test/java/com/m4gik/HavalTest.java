package com.m4gik;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;

import java.util.Arrays;
import java.util.Collection;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

/**
 * 
 * This class contains JUnit tests for class {@link Haval}.
 * 
 * @author Michał Szczygieł <michal.szczygiel@wp.pl>
 * 
 */
@RunWith(Parameterized.class)
public class HavalTest {

    @Parameterized.Parameters
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][] {
                { "The quick brown fox jumps over the lazy dog",
                        "713502673d67e5fa557629a71d331945",
                        HavalAttributes.HAVAL_128_BIT,
                        HavalAttributes.HAVAL_3_ROUND },
                { "The quick brown fox jumps over the lazy dog",
                        "6eece560a2e8d6b919e81fe91b0e7156",
                        HavalAttributes.HAVAL_128_BIT,
                        HavalAttributes.HAVAL_4_ROUND } });
    }

    private final String actualHash;

    private final String expectedHash;

    public HavalTest(String input, String expectedHash, Integer size,
            Integer rounds) {
        this.actualHash = new Haval(input, size, rounds).digest().toString();
        this.expectedHash = expectedHash;
    }

    @Test
    public void testHashIsNotNull() {
        assertThat(actualHash, is(notNullValue()));
    }

    @Test
    public void testHashIsValid() {
        assertThat(actualHash, is(equalTo(expectedHash)));
    }

    @Test(
            expected = IllegalArgumentException.class)
    public void testThrowsIfInputIsNull() {
        new Haval(null, HavalAttributes.HAVAL_128_BIT,
                HavalAttributes.HAVAL_5_ROUND);
    }

}