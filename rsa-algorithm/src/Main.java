import java.io.IOException;
/**
 * Project RSA Algorithm.
 * Copyright Michał Szczygieł.
 * Created at Feb 24, 2014.
 */

import org.apache.log4j.BasicConfigurator;
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
        BasicConfigurator.configure();
    }

    /**
     * @param args
     */
    public static void main(String[] args) {
        loggerSetup();
        RSA rsa = new RSA(1024);

        try {
            logger.info(IOOperations.encryptStream(
                    IOOperations.readFile("data.txt"), rsa, 10));
        } catch (IOException e) {
            logger.debug(e);
            logger.error(e);
        }
    }

}
