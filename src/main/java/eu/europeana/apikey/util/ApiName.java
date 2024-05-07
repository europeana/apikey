/**
 * Created by luthien on 18/04/2017.
 */

package eu.europeana.apikey.util;

/**
 * The enum Api name.
 */
public enum ApiName {

    /**
     * Search api name.
     */
    SEARCH("search", ""),
    /**
     * Entity api name.
     */
    ENTITY("entity", ""),
    /**
     * Annotation api name.
     */
    ANNOTATION("annotation", "");

    private String name;
    private String uri;

    /**
     *
     * @param name name of API
     * @param uri URL of API
     */
    ApiName(String name, String uri) {
        this.name = name;
        this.uri = uri;

    }

    @Override
    public String toString() {
        return name;
    }
}
