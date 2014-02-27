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
        Long number = rsa.calculateNumber(stream, blockSize);
        BigInteger encrypted = rsa.encrypt(new BigInteger(number.toString()));

        return encrypted.toByteArray();
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
     */
    public static OutputStream encryptStream(InputStream inputStream, RSA rsa,
            Integer blockSize) throws IOException {
        OutputStream outputStream = new ByteArrayOutputStream();
        Boolean encrytping = true;
        String allStream = "";
        Integer buffer = 0;
        Integer code = 0;

        while (encrytping) {

            if ((code = inputStream.read()) != -1) {
                allStream += code;

                if (++buffer == blockSize) {
                    outputStream
                            .write(encryptedData(rsa, allStream, blockSize));
                    allStream = "";
                    buffer = 0;
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
     * This method clears given parameters.
     * 
     * @param allStream
     *            The stream to clear.
     * @param buffer
     *            The buffer to clear.
     */
    private void clearStreamBuffer(String allStream, Integer buffer) {
        allStream = "";
        buffer = 0;
    }

    /**
     * This method encrypt given stream, using {@link RSA} object.
     * 
     * @param inputStream
     *            The {@link InputStream} with data to encrypt.
     */
    public void encryptStream(InputStream inputStream) {

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
