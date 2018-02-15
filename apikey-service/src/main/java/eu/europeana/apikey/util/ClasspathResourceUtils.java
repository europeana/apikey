package eu.europeana.apikey.util;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.io.InputStream;

public class ClasspathResourceUtils {
    private static final Logger LOG   = LogManager.getLogger(ClasspathResourceUtils.class);

    /**
     * Get a resource in classpath as a String
     * @param   path well, the path, obviously.
     * @return  String containing resource
     *
     * based on http://stackoverflow.com/a/5445161/204788
     *
     */
    public static String getResourceContentFromPath(String path) {
        try {
            try(InputStream is = ClasspathResourceUtils.class.getResourceAsStream(path)){
                java.util.Scanner s = new java.util.Scanner(is).useDelimiter("\\A");
                return s.hasNext() ? s.next() : "";
            }
        } catch (IOException e) {
            LOG.error("IOException thrown when reading property file: {}", e);
            throw new RuntimeException(e);
        }
    }
}
