/**
 * Project RSA Algorithm.
 * Copyright Michał Szczygieł.
 * Created at Feb 24, 2014.
 */

import java.io.IOException;
import java.io.OutputStream;

import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;

/**
 * This class is resposnible for testing and representation data for RSA
 * encryption algorithm.
 * 
 * @author Michał Szczygieł <michal.szczygiel@wp.pl>
 * 
 */
public class Main {

    /**
     * This logger is responsible for the registration of events.
     */
    static final Logger logger = LogManager.getLogger(Main.class.getName());

    /**
     * This method sets up configuration for loggers.
     */
    private static void loggerSetup() {
        // BasicConfigurator.configure();
    }

    /**
     * @param args
     */
    public static void main(String[] args) {
        if (args.length == 1) {
            loggerSetup();
            RSA rsa = new RSA(1024);

            try {
                OutputStream encryptedStream = IOOperations.encryptStream(
                        IOOperations.readFile(args[0]), rsa, RSA.BLOCK_SIZE);
                logger.info(encryptedStream.toString());
                logger.info(IOOperations.decryptStream(encryptedStream, rsa,
                        RSA.BLOCK_SIZE));
            } catch (IOException e) {
                logger.debug(e);
                logger.error(e);
            }
        } else {
            logger.warn("The application needs 1 argument as file to encrypt");
        }
    }

}
