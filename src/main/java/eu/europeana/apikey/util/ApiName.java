/**
 * Created by luthien on 18/04/2017.
 */

package eu.europeana.apikey.util;

public enum ApiName {

    SEARCH("search", ""),
    ENTITY("entity", ""),
    ANNOTATION("annotation", "");

    private String name;
    private String uri;

    ApiName(String name, String uri) {
        this.name = name;
        this.uri = uri;

    }

    @Override
    public String toString() {
        return name;
    }
}
