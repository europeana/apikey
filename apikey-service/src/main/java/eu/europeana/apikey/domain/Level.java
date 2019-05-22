package eu.europeana.apikey.domain;

/**
 * Created by luthien on 22/06/2017.
 */
public enum Level {

    CLIENT("CLIENT"),
    ADMIN("ADMIN");

    private final String levelName;

    Level(String levelName) {
        this.levelName = levelName;
    }

    public String getLevelName() {
        return levelName;
    }
}
