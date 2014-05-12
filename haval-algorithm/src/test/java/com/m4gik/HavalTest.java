package com.m4gik;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;

import java.util.Arrays;
import java.util.Collection;

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
        return Arrays
                .asList(new Object[][] {
                        { "The quick brown fox jumps over the lazy dog",
                                "713502673d67e5fa557629a71d331945",
                                HavalAttributes.HAVAL_128_BIT,
                                HavalAttributes.HAVAL_3_ROUND },
                        { "The quick brown fox jumps over the lazy dog",
                                "6eece560a2e8d6b919e81fe91b0e7156",
                                HavalAttributes.HAVAL_128_BIT,
                                HavalAttributes.HAVAL_4_ROUND },
                        { "The quick brown fox jumps over the lazy dog",
                                "696f02111f2e1da5c21d50eb782b7e8f",
                                HavalAttributes.HAVAL_128_BIT,
                                HavalAttributes.HAVAL_5_ROUND },
                        { "The quick brown fox jumps over the lazy dog",
                                "b338ac397e8bccadcccd96549cadd4882d834107",
                                HavalAttributes.HAVAL_160_BIT,
                                HavalAttributes.HAVAL_3_ROUND },
                        { "The quick brown fox jumps over the lazy dog",
                                "6e739d01f5739ceed94da1a115b52d5951280560",
                                HavalAttributes.HAVAL_160_BIT,
                                HavalAttributes.HAVAL_4_ROUND },
                        { "The quick brown fox jumps over the lazy dog",
                                "ecce9fa8a428866304ff082af2f9062637d36b23",
                                HavalAttributes.HAVAL_160_BIT,
                                HavalAttributes.HAVAL_5_ROUND },
                        {
                                "The quick brown fox jumps over the lazy dog",
                                "58e6ced002e311172483d434ba738ad033e7fa950e431503",
                                HavalAttributes.HAVAL_192_BIT,
                                HavalAttributes.HAVAL_3_ROUND },
                        {
                                "The quick brown fox jumps over the lazy dog",
                                "228ee09bc7e36151c6f285f558e6aede66ad38c8341592b9",
                                HavalAttributes.HAVAL_192_BIT,
                                HavalAttributes.HAVAL_4_ROUND },
                        {
                                "The quick brown fox jumps over the lazy dog",
                                "023d045f75d4bf051fd6e50f7b7417bf9949c4b5d2b4b7ef",
                                HavalAttributes.HAVAL_192_BIT,
                                HavalAttributes.HAVAL_5_ROUND },
                        {
                                "The quick brown fox jumps over the lazy dog",
                                "e1d5792306f56b22419662b06d1885a66dca3eba01f53274c89aeaeb",
                                HavalAttributes.HAVAL_224_BIT,
                                HavalAttributes.HAVAL_3_ROUND },
                        {
                                "The quick brown fox jumps over the lazy dog",
                                "dddd6689885f6db4ad91e35a35e1f4498446510df798d4fd54b8654f",
                                HavalAttributes.HAVAL_224_BIT,
                                HavalAttributes.HAVAL_4_ROUND },
                        {
                                "The quick brown fox jumps over the lazy dog",
                                "03d953298c8e56b46385c6761cd4b2e377889a75c97eaea475421c73",
                                HavalAttributes.HAVAL_224_BIT,
                                HavalAttributes.HAVAL_5_ROUND },
                        {
                                "The quick brown fox jumps over the lazy dog",
                                "9446028f42b3768a41bd873ca69b0c006341d986613567f39eb61f96ca683300",
                                HavalAttributes.HAVAL_256_BIT,
                                HavalAttributes.HAVAL_3_ROUND },
                        {
                                "The quick brown fox jumps over the lazy dog",
                                "c0d4c6ea514105fd1a9c38a238553fb7fa21d4127eb1a3035a75ce9d06a83d96",
                                HavalAttributes.HAVAL_256_BIT,
                                HavalAttributes.HAVAL_4_ROUND },
                        {
                                "The quick brown fox jumps over the lazy dog",
                                "b89c551cdfe2e06dbd4cea2be1bc7d557416c58ebb4d07cbc94e49f710c55be4",
                                HavalAttributes.HAVAL_256_BIT,
                                HavalAttributes.HAVAL_5_ROUND } });
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
        String hash = Haval.hash(input.getBytes(), size, rounds);
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
        assertThat(actualHash.toLowerCase(), is(equalTo(expectedHash)));
    }

    @Test
    public void testHavalWordProcessingOrders() {
        assertThat(HavalAttributes.WORD_PROCESSING_ORDER_1.length, is(32));
        assertThat(HavalAttributes.WORD_PROCESSING_ORDER_2.length, is(32));
        assertThat(HavalAttributes.WORD_PROCESSING_ORDER_3.length, is(32));
        assertThat(HavalAttributes.WORD_PROCESSING_ORDER_4.length, is(32));
        assertThat(HavalAttributes.WORD_PROCESSING_ORDER_5.length, is(32));
    }

    @Test
    public void testPadBufferResultSize() {
        // What
        Haval haval = new Haval();
        // When
        byte[] result = haval.padBuffer();
        // Then
        assertThat(result.length, is(greaterThan(10)));
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
