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

import org.springframework.util.StringUtils;
import java.util.Date;

public class Tools {

    public static String nvl(String input){
        return StringUtils.isEmpty(input) ? "" : input;
    }

    public static String nvl(Long input){
        return null == input ? "" : input.toString();
    }

    public static String nvl(Date input){
        return null == input ? "" : input.toString();
    }

}
