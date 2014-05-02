package com.m4gik;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

import org.junit.Test;
import org.mockito.Mockito;

/**
 * 
 * This class contains JUnit tests for class {@link BaseHash}.
 * 
 * @author Michał Szczygieł <michal.szczygiel@wp.pl>
 * 
 */
public class BaseHashTest {

    private BaseHash baseHash;

    @Test
    public void testProperBlockSize() {
        this.baseHash = Mockito.mock(BaseHash.class);
        Mockito.when(this.baseHash.blockSize()).thenReturn(
                HavalAttributes.HAVAL_192_BIT);
        assertThat(this.baseHash.blockSize(),
                is(equalTo(HavalAttributes.HAVAL_192_BIT)));
    }

    @Test
    public void testTheProperGivenName() {
        this.baseHash = Mockito.mock(BaseHash.class);
        Mockito.when(this.baseHash.name()).thenReturn("Haval");
        assertThat(this.baseHash.name(), is(equalTo("Haval")));
    }

    @Test(
            expected = IllegalArgumentException.class)
    public void testThrowsIfNameIsEmptyOrNull() {
        this.baseHash = Mockito
                .mock(BaseHash.class, Mockito.CALLS_REAL_METHODS);
        Mockito.when(this.baseHash.name()).thenReturn("Haval");
        assertThat(new BaseHash(null, 2, 3) {

            @Override
            public Object clone() {
                return null;
            }

            @Override
            protected byte[] getResult() {
                return null;
            }

            @Override
            protected byte[] padBuffer() {
                return null;
            }

            @Override
            protected void resetContext() {
            }

            @Override
            protected void transform(byte[] in, int offset) {
            }
        }.name(), is(equalTo("Haval")));
    }

    @Test(
            expected = IllegalArgumentException.class)
    public void testThrowsIfSizeOfOutputIsLessThenZero() {
        this.baseHash = new BaseHash(null, 0, 0) {

            @Override
            public Object clone() {
                return null;
            }

            @Override
            protected byte[] getResult() {
                return null;
            }

            @Override
            protected byte[] padBuffer() {
                return null;
            }

            @Override
            protected void resetContext() {
            }

            @Override
            protected void transform(byte[] in, int offset) {

            }
        };
    }
}
