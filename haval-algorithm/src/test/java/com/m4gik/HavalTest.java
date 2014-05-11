package com.m4gik;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;

import java.util.Arrays;
import java.util.Collection;

import javax.crypto.IllegalBlockSizeException;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import com.m4gik.util.Util;

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

    private final String input;

    private final Integer rounds;

    private final Integer size;

    public HavalTest(String input, String expectedHash, Integer size,
            Integer rounds) {
        this.actualHash = Util.toString(new Haval(input.getBytes(), size,
                rounds).digest());
        this.input = input;
        this.expectedHash = expectedHash;
        this.size = size;
        this.rounds = rounds;
    }

    @Test
    public void testCheckStaticHashing() {
        // When
        String hash = Haval.hash(input.getBytes(),
                HavalAttributes.HAVAL_128_BIT, HavalAttributes.HAVAL_3_ROUND);
        // Then
        assertThat(hash, is(equalTo(expectedHash)));
    }

    @Test
    public void testCloneMethod() {
        // What
        Haval haval = new Haval();
        Haval havalClone;
        // When
        havalClone = (Haval) haval.clone();
        // Then
        assertThat(havalClone, is(instanceOf(Haval.class)));
        assertThat(havalClone.hashSize(), is(haval.hashSize));
        assertThat(havalClone.getRounds(), is(haval.getRounds()));
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
            expected = IllegalBlockSizeException.class)
    public void testPadBufferResultSize() {
        // What
        Haval haval = new Haval();
        // When
        byte[] result = haval.padBuffer();
        // Then
        assertThat(result.length % HavalAttributes.BLOCK_SIZE, is(0));
    }

    @Test
    public void testPositiveScenarioOfAmountRounds() {
        new Haval(size, rounds);
    }

    @Test
    public void testPositiveScenarioOfOutputSize() {
        new Haval(HavalAttributes.HAVAL_128_BIT, rounds);
    }

    @Test(
            expected = IllegalArgumentException.class)
    public void testThrowsIfInputIsNull() {
        new Haval(null, size, rounds);
    }

    @Test(
            expected = IllegalArgumentException.class)
    public void testThrowsIfRoundsIsWrong() {
        new Haval(size, -1);
    }

    @Test(
            expected = IllegalArgumentException.class)
    public void testThrowsIfSizeIsWrong() {
        new Haval(HavalAttributes.HAVAL_128_BIT - 1, rounds);
    }

}
