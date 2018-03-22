/*
 * Copyright 2007-2017 The Europeana Foundation
 *
 *  Licenced under the EUPL, Version 1.1 (the "Licence") and subsequent versions as approved
 *  by the European Commission;
 *  You may not use this work except in compliance with the Licence.
 *
 *  You may obtain a copy of the Licence at:
 *  http://joinup.ec.europa.eu/software/page/eupl
 *
 *  Unless required by applicable law or agreed to in writing, software distributed under
 *  the Licence is distributed on an "AS IS" basis, without warranties or conditions of
 *  any kind, either express or implied.
 *  See the Licence for the specific language governing permissions and limitations under
 *  the Licence.
 */


/**
 * Created by luthien on 18/04/2017.
 */

package eu.europeana.apikey.util;

import org.apache.commons.lang.math.RandomUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.util.StringUtils;

import java.util.Date;
import java.util.Random;

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
        LOG.debug("generate new random passphrase with length: " + length);
        Random random = new Random();
        final char[] allowableCharacters = new char[]{'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'm',
                'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G',
                'H', 'J', 'K', 'L', 'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '2', '3', '4',
                '5', '6', '7', '8', '9'};

        final int max = allowableCharacters.length - 1;
        StringBuilder pass = new StringBuilder();
        for (int i = 0; i < length; i++) {
            pass.append(allowableCharacters[RandomUtils.nextInt(random, max)]);
        }
        return pass.toString();
    }

}
