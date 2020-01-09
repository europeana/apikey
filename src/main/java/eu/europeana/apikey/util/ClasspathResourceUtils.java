package eu.europeana.apikey.util;

import java.io.IOException;
import java.io.InputStream;

public class ClasspathResourceUtils {

    private ClasspathResourceUtils(){}

    /**
     * Get a resource in classpath as a String
     * @param   path well, the path, obviously.
     * @return  String containing resource
     *
     * based on http://stackoverflow.com/a/5445161/204788
     *
     */
    public static String getResourceContentFromPath(String path) throws IOException{
        try(
            InputStream is = ClasspathResourceUtils.class.getResourceAsStream(path)){
            java.util.Scanner s = new java.util.Scanner(is).useDelimiter("\\A");
            return s.hasNext() ? s.next() : "";
        }
    }
}
