/**
 * Project RSA Algorithm.
 * Copyright Michał Szczygieł.
 * Created at Feb 25, 2014.
 */

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

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
     * This method encrypt given stream, using {@link RSA} object.
     * 
     * @param inputStream
     *            The {@link InputStream} with data to encrypt.
     * @param rsa
     *            The instance of {@link RSA} encryption.
     */
    public static void encryptStream(InputStream inputStream, RSA rsa) {

    }

    /**
     * Object to keep instance of {@link RSA}.
     */
    private RSA rsa;

    /**
     * The constructor for {@link IOOperations}, which crate instance of this
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
     */
    public void encryptStream(InputStream inputStream) {

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
     * This method reads file from given directory.
     * 
     * @param filePath
     *            The directory for file.
     * @return The {@link InputStream} for read file.
     * @throws IOException
     */
    public InputStream readFile(String filePath) throws IOException {
        InputStream InputStream = null;
        File file = new File(filePath);

        if (file.exists()) {
            InputStream = new FileInputStream(file);
        }

        return InputStream;
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
