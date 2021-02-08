/**
 * Created by luthien on 18/04/2017.
 */

package eu.europeana.apikey.util;

import org.apache.commons.lang3.RandomUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.util.StringUtils;

import java.util.Date;

public final class Tools {

    private Tools(){}

    private static final Logger LOG = LogManager.getLogger(Tools.class);

    public static String nvl(String input){
        return StringUtils.isEmpty(input) ? "" : input;
    }

    public static String nvl(Long input){
        return null == input ? "" : input.toString();
    }

    public static String nvl(Date input){
        return null == input ? "" : input.toString();
    }

    public static String generatePassPhrase(int length) {
        // This variable contains the list of allowable characters for the
        // pass phrase. Note that the number 0 and the letter 'O' have been
        // removed to avoid confusion between the two. The same is true
        // of 'I', 1, and 'l'.
        LOG.debug("generate new random passphrase with length: {}", length);
        final char[] allowableCharacters = new char[]{'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'm',
                'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G',
                'H', 'J', 'K', 'L', 'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '2', '3', '4',
                '5', '6', '7', '8', '9'};

        StringBuilder pass = new StringBuilder();
        for (int i = 0; i < length; i++) {
            pass.append(allowableCharacters[RandomUtils.nextInt(0, allowableCharacters.length)]);
        }
        return pass.toString();
    }

}
