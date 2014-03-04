/**
 * Project RSA Algorithm.
 * Copyright Michał Szczygieł.
 * Created at Feb 25, 2014.
 */

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;

import org.apache.commons.lang3.StringUtils;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;

/**
 * 
 * This class is responsible for safe operations on files. This class contain
 * the basic input/output operations.
 * 
 * @author Michał Szczygieł <michal.szczygiel@wp.pl>
 * 
 */
public class IOOperations {

    /**
     * This logger is responsible for the registration of events.
     */
    static final Logger logger = LogManager.getLogger(IOOperations.class
            .getName());

    /**
     * The constant value represents the character to separate blocks.
     */
    private final static String SEPARATOR = "~";

    /**
     * This method clears given parameter.
     * 
     * @param data
     *            The data to clear
     * @return Cleared data.
     */
    private static Object clearStreamBuffer(Object data) {
        Object clear = null;

        if (data instanceof Integer) {
            clear = 0;
        }

        if (data instanceof String) {
            clear = "";
        }

        return clear;
    }

    /**
     * This method makes process of decryption for given stream data.
     * 
     * @param rsa
     *            The {@link RSA} instance.
     * @param stream
     *            The stream of data to decrypt.
     * @param blockSize
     *            The size for block of data to decrypt.
     * @return The decrypted data as byte array.
     */
    private static byte[] decryptedData(RSA rsa, String streamBlock,
            Integer blockSize) {
        String decrypted = rsa.decrypt(streamBlock);
        BigInteger number = new BigInteger(decrypted);

        return rsa.translateToString(number, blockSize).getBytes();
    }

    /**
     * This method makes process of decryption for given stream data.
     * 
     * @param outputStream
     *            The {@link OutputStream} with data to encrypt.
     * @param rsa
     *            The instance of {@link RSA} encryption.
     * @param blockSize
     *            The size of block for fragmentation data.
     * @return The decrypted data as {@link OutputStream}.
     * @throws IOException
     */
    public static OutputStream decryptStream(OutputStream outputStream,
            RSA rsa, Integer blockSize) throws IOException {
        OutputStream decryptedStream = new ByteArrayOutputStream();
        String allStream = "";

        if ((allStream = outputStream.toString()).length() != 0) {
            String[] encrypted = allStream.split(SEPARATOR.toString());

            for (String streamBlock : encrypted) {
                decryptedStream
                        .write(decryptedData(rsa, streamBlock, blockSize));
            }
        }

        return decryptedStream;
    }

    /**
     * This method makes process of encryption for given stream data.
     * 
     * @param rsa
     *            The {@link RSA} instance.
     * @param stream
     *            The stream of data to encrypt.
     * @param blockSize
     *            The size for block of data to encrypt.
     * @return The encrypted data as byte array.
     */
    private static byte[] encryptedData(RSA rsa, String stream,
            Integer blockSize) {
        BigInteger number = rsa.translateToBigInteger(stream, blockSize);
        String encrypted = rsa.encrypt(number.toString());

        return encrypted.getBytes();
    }

    /**
     * This method encrypt given stream, using {@link RSA} object.
     * 
     * @param inputStream
     *            The {@link InputStream} with data to encrypt.
     * @param rsa
     *            The instance of {@link RSA} encryption.
     * 
     * @param blockSize
     *            The size of block for fragmentation data.
     * @return The encrypted data as {@link OutputStream}.
     * @throws IOException
     */
    public static OutputStream encryptStream(InputStream inputStream, RSA rsa,
            Integer blockSize) throws IOException {
        OutputStream outputStream = new ByteArrayOutputStream();
        Boolean encrytping = true;
        String allStream = "";
        Integer buffer = 0;
        int code = 0;

        while (encrytping) {

            if ((code = inputStream.read()) != -1) {
                allStream += (char) code;

                if (++buffer == blockSize) {
                    outputStream
                            .write(encryptedData(rsa, allStream, blockSize));
                    outputStream.write(separatorToByte(SEPARATOR));
                    logger.info(outputStream.toString());
                    allStream = (String) clearStreamBuffer(allStream);
                    buffer = (Integer) clearStreamBuffer(buffer);
                }

            } else {

                if (buffer != 0) {
                    allStream = StringUtils.rightPad(allStream, blockSize,
                            RSA.PADDING);
                    outputStream
                            .write(encryptedData(rsa, allStream, blockSize));
                }

                encrytping = false;
            }

        }

        return outputStream;
    }

    /**
     * This method reads file from given directory.
     * 
     * @param filePath
     *            The directory for file.
     * @return The {@link InputStream} for read file.
     * @throws IOException
     */
    public static InputStream readFile(String filePath) throws IOException {
        InputStream InputStream = null;
        File file = new File(filePath);

        if (file.exists()) {
            InputStream = new FileInputStream(file);
        }

        return InputStream;
    }

    /**
     * This method gets byte array of given character.
     * 
     * @param character
     *            The character to separate blocks.
     * @return The byte array of given character.
     */
    private static byte[] separatorToByte(String character) {
        return character.getBytes();
    }

    /**
     * The size for fragmentation data.
     */
    private Integer blockSize = RSA.BLOCK_SIZE;

    /**
     * Object to keep instance of {@link RSA}.
     */
    private RSA rsa;

    /**
     * The constructor for {@link IOOperations}, which create instance of this
     * class.
     */
    public IOOperations() {
    }

    /**
     * The constructor for {@link IOOperations}, which create instance of this
     * class.
     * 
     * @param rsa
     *            The instance of {@link RSA} encryption.
     */
    public IOOperations(RSA rsa) {
        this.setRsa(rsa);
    }

    /**
     * This method encrypt given stream, using {@link RSA} object.
     * 
     * @param inputStream
     *            The {@link InputStream} with data to encrypt.
     * @throws IOException
     */
    public OutputStream encryptStream(InputStream inputStream)
            throws IOException {
        OutputStream outputStream = new ByteArrayOutputStream();
        Boolean encrytping = true;
        String allStream = "";
        Integer buffer = 0;
        int code = 0;

        while (encrytping) {

            if ((code = inputStream.read()) != -1) {
                allStream += (char) code;

                if (++buffer == blockSize) {
                    outputStream
                            .write(encryptedData(rsa, allStream, blockSize));
                    outputStream.write(separatorToByte(SEPARATOR));
                    allStream = (String) clearStreamBuffer(allStream);
                    buffer = (Integer) clearStreamBuffer(buffer);
                }

            } else {

                if (buffer != 0) {
                    allStream = StringUtils.rightPad(allStream, blockSize,
                            RSA.PADDING);
                    outputStream
                            .write(encryptedData(rsa, allStream, blockSize));
                }

                encrytping = false;
            }

        }

        return outputStream;
    }

    /**
     * This method gets current size for block to encrypt.
     * 
     * @return The size of block to encrypt.
     */
    public Integer getBlockSize() {
        return blockSize;
    }

    /**
     * This method gets {@link RSA} instance.
     * 
     * @return the {@link RSA} instance.
     */
    public RSA getRsa() {
        return rsa;
    }

    /**
     * This method sets size of block to encrypt.
     * 
     * @param blockSize
     *            The size of block to set
     */
    public void setBlockSize(Integer blockSize) {
        this.blockSize = blockSize;
    }

    /**
     * This method sets {@link RSA} instance.
     * 
     * @param rsa
     *            The {@link RSA} to set
     */
    public void setRsa(RSA rsa) {
        this.rsa = rsa;
    }

    /**
     * This method creates output stream to write into file.
     * 
     * @param filePath
     *            The directory for file location.
     * @return The {@link OutputStream} for file to write.
     * @throws FileNotFoundException
     */
    public OutputStream writeFile(String filePath) throws FileNotFoundException {
        OutputStream outputStream = null;
        File file = new File(filePath);

        if (file.exists()) {
            outputStream = new FileOutputStream(file);
        }

        return outputStream;
    }

}
