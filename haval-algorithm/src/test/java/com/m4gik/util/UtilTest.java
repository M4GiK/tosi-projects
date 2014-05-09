package com.m4gik.util;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;

import java.util.Arrays;
import java.util.Collection;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

/**
 * 
 * This class contains JUnit tests for class {@link Util}.
 * 
 * @author Michał Szczygieł <michal.szczygiel@wp.pl>
 * 
 */
@RunWith(Parameterized.class)
public class UtilTest {

    @Parameterized.Parameters
    public static Collection<Object[]> data() {
        return Arrays
                .asList(new Object[][] {
                        { new String("713502673d67e5fa557629a71d331945")
                                .getBytes() },
                        { new String("6eece560a2e8d6b919e81fe91b0e7156")
                                .getBytes() }, });
    }

    private final Object input;

    public UtilTest(Object input) {
        this.input = input;
    }

    @Test
    public void testInputIsNotNull() {
        assertThat(input, is(notNullValue()));
    }

    @Test(
            expected = NumberFormatException.class)
    public void testThrowIfGivenStingIsNotHexValue() {
        Util.toString((byte[]) input);
    }
}
