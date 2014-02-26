import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Project RSA Algorithm.
 * Copyright Michał Szczygieł.
 * Created at Feb 25, 2014.
 */

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
     * Object to keep instance of RSA.
     */
    private RSA rsa;

    /**
     * 
     * @param rsa
     */
    public IOOperations(RSA rsa) {
        this.setRsa(rsa);
    }

    /**
     * This method gets RSA instance.
     * 
     * @return the RSA instance.
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
     * This method sets RSA instance.
     * 
     * @param rsa
     *            The RSA to set
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
