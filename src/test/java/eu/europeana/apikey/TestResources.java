package eu.europeana.apikey;

import eu.europeana.apikey.config.KeycloakProperties;
import eu.europeana.apikey.domain.ApiKey;
import eu.europeana.apikey.domain.ApiKeyRequest;

/**
 * Created by luthien on 26/01/2021.
 */
public class TestResources {

    private static final String CREDENTIAL_REPRESENTATION = "{\n"
            + "    \"type\": \"secret\",\n"
            + "    \"value\": \"134d4ec9-a26e-4dcb-93b7-13e22606eb9d\"\n"
            + "}";


    private static final String DISABLED_CLIENT_REPRESENTATIONS = "[\n"
            + "    {\n"
            + "        \"id\": \"fff0fb90-739d-448e-b511-3738af0a2355\",\n"
            + "        \"clientId\": \"test-add-rest\",\n"
            + "        \"surrogateAuthRequired\": false,\n"
            + "        \"enabled\": false,\n"
            + "        \"clientAuthenticatorType\": \"client-secret\",\n"
            + "        \"redirectUris\": [],\n"
            + "        \"webOrigins\": [],\n"
            + "        \"notBefore\": 0,\n"
            + "        \"bearerOnly\": false,\n"
            + "        \"consentRequired\": false,\n"
            + "        \"standardFlowEnabled\": true,\n"
            + "        \"implicitFlowEnabled\": false,\n"
            + "        \"directAccessGrantsEnabled\": false,\n"
            + "        \"serviceAccountsEnabled\": false,\n"
            + "        \"publicClient\": false,\n"
            + "        \"frontchannelLogout\": false,\n"
            + "        \"protocol\": \"openid-connect\",\n"
            + "        \"attributes\": {},\n"
            + "        \"authenticationFlowBindingOverrides\": {},\n"
            + "        \"fullScopeAllowed\": true,\n"
            + "        \"nodeReRegistrationTimeout\": -1,\n"
            + "        \"defaultClientScopes\": [\n"
            + "            \"web-origins\",\n"
            + "            \"role_list\",\n"
            + "            \"profile\",\n"
            + "            \"roles\",\n"
            + "            \"email\"\n"
            + "        ],\n"
            + "        \"optionalClientScopes\": [\n"
            + "            \"address\",\n"
            + "            \"phone\",\n"
            + "            \"offline_access\"\n"
            + "        ],\n"
            + "        \"access\": {\n"
            + "            \"view\": true,\n"
            + "            \"configure\": true,\n"
            + "            \"manage\": true\n"
            + "        }\n"
            + "    }\n"
            + "]";

    private static final String CLIENT_REPRESENTATIONS = "[\n"
            + "    {\n"
            + "        \"id\": \"fff0fb90-739d-448e-b511-3738af0a2355\",\n"
            + "        \"clientId\": \"test-add-rest\",\n"
            + "        \"surrogateAuthRequired\": false,\n"
            + "        \"enabled\": true,\n"
            + "        \"clientAuthenticatorType\": \"client-secret\",\n"
            + "        \"redirectUris\": [],\n"
            + "        \"webOrigins\": [],\n"
            + "        \"notBefore\": 0,\n"
            + "        \"bearerOnly\": false,\n"
            + "        \"consentRequired\": false,\n"
            + "        \"standardFlowEnabled\": true,\n"
            + "        \"implicitFlowEnabled\": false,\n"
            + "        \"directAccessGrantsEnabled\": false,\n"
            + "        \"serviceAccountsEnabled\": false,\n"
            + "        \"publicClient\": false,\n"
            + "        \"frontchannelLogout\": false,\n"
            + "        \"protocol\": \"openid-connect\",\n"
            + "        \"attributes\": {},\n"
            + "        \"authenticationFlowBindingOverrides\": {},\n"
            + "        \"fullScopeAllowed\": true,\n"
            + "        \"nodeReRegistrationTimeout\": -1,\n"
            + "        \"defaultClientScopes\": [\n"
            + "            \"web-origins\",\n"
            + "            \"role_list\",\n"
            + "            \"profile\",\n"
            + "            \"roles\",\n"
            + "            \"email\"\n"
            + "        ],\n"
            + "        \"optionalClientScopes\": [\n"
            + "            \"address\",\n"
            + "            \"phone\",\n"
            + "            \"offline_access\"\n"
            + "        ],\n"
            + "        \"access\": {\n"
            + "            \"view\": true,\n"
            + "            \"configure\": true,\n"
            + "            \"manage\": true\n"
            + "        }\n"
            + "    }\n"
            + "]";


    private static final String SUCCESSFULLYCREATEDKEY = "keytosuccess";
    private static final String SUCCESSFULFIRSTNAME = "Simon";
    private static final String SUCCESSFULLASTNAME = "Success";
    private static final String SUCCESSFULEMAIL = "successful.simon@hugely.successful.org";
    private static final String SUCCESSFULAPPNAME = "SuccessAgenda";
    private static final String SUCCESSFULCOMPANY = "VerySuccessfulOrg";
    private static final String SUCCESSFULSECTOR = "Successsector";
    private static final String SUCCESSFULWEBSITE = "https://hugely.successful.org";

    private static final String CAPTCHAKEY = "captchakey";
    private static final String CAPTCHAFIRSTNAME = "Carola";
    private static final String CAPTCHALASTNAME = "Captchame";
    private static final String CAPTCHAEMAIL = "captchameifyoudare@gmail.com";
    private static final String CAPTCHAAPPNAME = "Lalalillylooper";
    private static final String CAPTCHACOMPANY = "Carolaorganisation";

    private static final String UPDATEKEY = "updatekey";
    private static final String UPDATEFIRSTNAME = "Ulrike";
    private static final String UPDATELASTNAME = "Updatenmachtjaspass";
    private static final String UPDATEEMAIL = "updatenmachtspass@gmail.com";
    private static final String UPDATEAPPNAME = "Abersojadoch";
    private static final String UPDATECOMPANY = "Ulrikefoundation";

    private static final String EXISTINGKEY1 = "existingkey1";
    private static final String EXISTINGFIRSTNAME1 = "Edward";
    private static final String EXISTINGLASTNAME1 = "Existing";
    public static final String EXISTINGEMAIL1 = "edflopps@mail.com";
    public static final String EXISTINGAPPNAME1 = "ThisAppExists";
    private static final String EXISTINGCOMPANY1 = "ExistingFoundation";

    private static final String EXISTINGKEY2 = "existingkey2";
    private static final String EXISTINGFIRSTNAME2 = "Elsbeth";
    private static final String EXISTINGLASTNAME2 = "Existingtoo";
    private static final String EXISTINGEMAIL2 = "twinspizzlefix@sneeze.org";
    private static final String EXISTINGAPPNAME2 = "ThisAppExistsToo";
    private static final String EXISTINGCOMPANY2 = "ExistingCompany";

    private static final String UNREGISTEREDKEY = "unregisteredkey";
    private static final String UNREGISTEREDFIRSTNAME = "Dwight D.";
    private static final String UNREGISTEREDLASTNAME = "Deprecated";
    private static final String UNREGISTEREDEMAIL = "nononononever@kritzle.me";
    private static final String UNREGISTEREDAPPNAME = "UnregisteredAppAndDeprecatedToo";
    private static final String UNREGISTEREDCOMPANY = "UnregistrableOrganisation";


    private static final String MIGRATEDKEY = "migratedkey";
    private static final String MIGRATEDFIRSTNAME = "Minko";
    private static final String MIGRATEDLASTNAME = "The Migrator";
    private static final String MIGRATEDEMAIL = "migrate@migrate.yes";
    private static final String MIGRATEDAPPNAME = "MigratedApp";
    private static final String MIGRATEDCOMPANY = "MigratableBusiness";
    private static final String MIGRATEDSECTOR = "A Completely Different Sector Altogether";


    private static final String DEPRECATED_API_KEY = "apikey4";
    private static final String NEW_API_KEY = "apikey5";
    private static final String CAPTCHA_API_KEY = "apikey6";
    private static final String MIGRATE_API_KEY = "to-migrate";
    private static final String NON_EXISTIG_API_KEY = "testing";
    private static final String NEW_KEYCLOAKID = "apikey7";

    private static final String CAPTCHA_TOKEN = "token";

    private static final String ACCESS_TOKEN_STRING = "token1";
    private static final String ACCESS_TOKEN_STRING_REFRESHED = "token2";

    private static final String TOKEN
            = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJ3Y1N6TDZ0a3RCNFhHcUtjbEZncnVaaHQtX3d5MkZUV0FlWUtaYWNSOTNnIn0.eyJqdGkiOiJmMzZlNWUwZS04Zjk1LTQzNmMtODNiOC1jOTRmNDcyZWRlNTQiLCJleHAiOjE1NTcyNjY1NjksIm5iZiI6MCwiaWF0IjoxNTU3MjMwNTY5LCJpc3MiOiJodHRwczovL2tleWNsb2FrLXNlcnZlci10ZXN0LmVhbmFkZXYub3JnL2F1dGgvcmVhbG1zL2V1cm9wZWFuYSIsImF1ZCI6InJlYWxtLW1hbmFnZW1lbnQiLCJzdWIiOiJkZTg5MGI1OS03NTFjLTRmNjMtYWUxYS1mODc5ODlkNDU1ZDUiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJhcGkta2V5LXNlcnZpY2UiLCJhdXRoX3RpbWUiOjAsInNlc3Npb25fc3RhdGUiOiIzMGI2ZDkxNy0wMWIzLTRmMTItYmYyMi1lZjkxOWQ0ZjdiZDQiLCJhY3IiOiIxIiwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbIkFQSSJdfSwicmVzb3VyY2VfYWNjZXNzIjp7ImFwaS1rZXktc2VydmljZSI6eyJyb2xlcyI6WyJ1bWFfcHJvdGVjdGlvbiJdfSwicmVhbG0tbWFuYWdlbWVudCI6eyJyb2xlcyI6WyJ2aWV3LXJlYWxtIiwidmlldy1pZGVudGl0eS1wcm92aWRlcnMiLCJtYW5hZ2UtaWRlbnRpdHktcHJvdmlkZXJzIiwiaW1wZXJzb25hdGlvbiIsInJlYWxtLWFkbWluIiwiY3JlYXRlLWNsaWVudCIsIm1hbmFnZS11c2VycyIsInF1ZXJ5LXJlYWxtcyIsInZpZXctYXV0aG9yaXphdGlvbiIsInF1ZXJ5LWNsaWVudHMiLCJxdWVyeS11c2VycyIsIm1hbmFnZS1ldmVudHMiLCJtYW5hZ2UtcmVhbG0iLCJ2aWV3LWV2ZW50cyIsInZpZXctdXNlcnMiLCJ2aWV3LWNsaWVudHMiLCJtYW5hZ2UtYXV0aG9yaXphdGlvbiIsIm1hbmFnZS1jbGllbnRzIiwicXVlcnktZ3JvdXBzIl19fSwic2NvcGUiOiJvcGVuaWQgZW1haWwgcHJvZmlsZSIsImNsaWVudElkIjoiYXBpLWtleS1zZXJ2aWNlIiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJjbGllbnRIb3N0IjoiMTUwLjI1NC4xNjkuMTAwIiwicHJlZmVycmVkX3VzZXJuYW1lIjoic2VydmljZS1hY2NvdW50LWFwaS1rZXktc2VydmljZSIsImNsaWVudEFkZHJlc3MiOiIxNTAuMjU0LjE2OS4xMDAiLCJlbWFpbCI6InNlcnZpY2UtYWNjb3VudC1hcGkta2V5LXNlcnZpY2VAcGxhY2Vob2xkZXIub3JnIn0.UoENMoInw81KRWkRW7divlPpGjKTgluZaU2cyZOqw7TU92cg7b2ELFBtv-Myc1rmap2Ha-VaKRc5cVsR_wwIiqYPELkwSTqC8yMNjEJdfg0MQyDnCtxP_72ehgP9YRhMrR1JB1TeXMChhwn1BDpdRQYdZjxRQCSArGy_lQHlDjU5hLJbdV3ZWjq8-l-uIWuJiviMHG2I3J34ioyKEEi6Xo7OhclXjcQ-OmPYRBTnGZBu908IFH9b23NxOOssPZxzYr3n6Qf9HPoaJ_VEja1OOeHDCCJcBtw4ww8TnkcRaA1llugBSS5iO9Fku_CZqEEeMkG3OdUpyn7Cuzahuac5KA";
    private static final String REALM_PUBLIC_KEY
            = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAgq2lkW7yOWM1mEIyE3zvJxHoRX6S9U8GJp3leNent2E7CXffk45clrpA2ElzH7OAWEoKEth+ORlHAeyAls4eqTyjimXv4HRVTxxL9PCrQDqsd9oVKXnQPbLYxaMRN9xLF2THBYVNJv7Bz1DT3CL+DAq9f5W9N0X+Nsik2+IE8IUDLWyfY2COQrpfS3gTTzHyt7BFDUbzvOuLs6jRuA2rFyYv1i8dN6vdX7WiamrLyTBLOLNGWwCCuV4qLdhbKMUl7S3jOkPg7WHy+lfkWmWAdeSP9wPTDnSJXpCIb+dbYUW6mhlbLNfQLksjxDAqLCE8MgMD6n/CJgVvf26GhlRxWQIDAQAB";
    private static final String APP_NAME = "App name";
    private static final String WEBSITE = "www.website.com";
    private static final String SECTOR = "Sector";
    private static final String COMPANY = "Company";
    private static final String CLIENT_ID = "client";
    private static final String CLIENT_SECRET = "secret";
    private static final String NEW_CLIENT_SECRET = "134d4ec9-a26e-4dcb-93b7-13e22606eb9d";
    private static final String EMPTY_CLIENT_REPRESENTATIONS = "[]";
    private static final String FIRST_NAME = "Name";
    private static final String LAST_NAME = "Surname";
    private static final String EMAIL = "name.surname@mail.com";

    private static final String MANAGER_CLIENT_ID = "manager";
    private static final String MANAGER_CLIENT_SECRET = "secret";
    private static final String ROLE_CREATE_CLIENT = "realm-create-client";
    private static final String RESOURCE_ACCESS = "access";

    private static final String UNSUCCESSFUL_RESPONSE
            = "{\"success\": false,\"error-codes\": [\"invalid-input-response\"]}";

    private static final String SUCCESSFUL_RESPONSE = "{\"success\": true,\"error-codes\": []}";


    public static KeycloakProperties getKeycloakProperties() {
        return new KeycloakProperties("https://keycloak-cf-test.eanadev.org/auth",
                "europeana",
                true,
                TestResources.getRealmPublicKey());
    }

    public static ApiKeyRequest getSuccessfulApiKeyRequest() {
        return new ApiKeyRequest(SUCCESSFULFIRSTNAME, SUCCESSFULLASTNAME, SUCCESSFULEMAIL, SUCCESSFULAPPNAME, SUCCESSFULCOMPANY, SUCCESSFULSECTOR, SUCCESSFULWEBSITE);
    }

    public static ApiKeyRequest getCaptchaApiKeyRequest() {
        return new ApiKeyRequest(CAPTCHAFIRSTNAME, CAPTCHALASTNAME, CAPTCHAEMAIL, CAPTCHAAPPNAME, CAPTCHACOMPANY);
    }

    public static ApiKeyRequest getUpdateApiKeyRequest() {
        return new ApiKeyRequest(UPDATEFIRSTNAME, UPDATELASTNAME, UPDATEEMAIL, UPDATEAPPNAME, UPDATECOMPANY);
    }

    public static ApiKey getSuccessfullyCreatedApiKey() {
        ApiKey successfullyCreatedApiKey = new ApiKey(SUCCESSFULLYCREATEDKEY, SUCCESSFULFIRSTNAME, SUCCESSFULLASTNAME, SUCCESSFULEMAIL, SUCCESSFULAPPNAME, SUCCESSFULCOMPANY);
        successfullyCreatedApiKey.setSector(SUCCESSFULSECTOR);
        successfullyCreatedApiKey.setWebsite(SUCCESSFULWEBSITE);
        return successfullyCreatedApiKey;
    }

    public static ApiKey getCaptchaCreatedApiKey() {
        return new ApiKey(CAPTCHAKEY, CAPTCHAFIRSTNAME, CAPTCHALASTNAME, CAPTCHAEMAIL, CAPTCHAAPPNAME, CAPTCHACOMPANY);
    }

    public static ApiKey getUpdatedApiKey() {
        return new ApiKey(UPDATEKEY, UPDATEFIRSTNAME, UPDATELASTNAME, UPDATEEMAIL, UPDATEAPPNAME, UPDATECOMPANY);
    }

    public static ApiKey getExistingApiKey1() {
        return new ApiKey(EXISTINGKEY1, EXISTINGFIRSTNAME1, EXISTINGLASTNAME1, EXISTINGEMAIL1, EXISTINGAPPNAME1, EXISTINGCOMPANY1);
    }

    public static ApiKey getExistingApiKey2() {
        return new ApiKey(EXISTINGKEY2, EXISTINGFIRSTNAME2, EXISTINGLASTNAME2, EXISTINGEMAIL2, EXISTINGAPPNAME2, EXISTINGCOMPANY2);
    }

    public static ApiKey getUnregisteredApiKey() {
        return new ApiKey(UNREGISTEREDKEY, UNREGISTEREDFIRSTNAME, UNREGISTEREDLASTNAME, UNREGISTEREDEMAIL, UNREGISTEREDAPPNAME, UNREGISTEREDCOMPANY);
    }

    public static ApiKey getMigratedApiKey() {
        ApiKey migratedApiKey = new ApiKey(MIGRATEDKEY, MIGRATEDFIRSTNAME, MIGRATEDLASTNAME, MIGRATEDEMAIL, MIGRATEDAPPNAME, MIGRATEDCOMPANY);
        migratedApiKey.setSector(MIGRATEDSECTOR);
        return migratedApiKey;
    }


    public static String getCredentialRepresentation() {
        return CREDENTIAL_REPRESENTATION;
    }

    public static String getDisabledClientRepresentations() {
        return DISABLED_CLIENT_REPRESENTATIONS;
    }

    public static String getClientRepresentations() {
        return CLIENT_REPRESENTATIONS;
    }

    public static String getToken() {
        return TOKEN;
    }

    public static String getRealmPublicKey() {
        return REALM_PUBLIC_KEY;
    }

    public static String getAppName() {
        return APP_NAME;
    }

    public static String getWebsite() {
        return WEBSITE;
    }

    public static String getSector() {
        return SECTOR;
    }

    public static String getCompany() {
        return COMPANY;
    }

    public static String getClientId() {
        return CLIENT_ID;
    }

    public static String getClientSecret() {
        return CLIENT_SECRET;
    }

    public static String getNewClientSecret() {
        return NEW_CLIENT_SECRET;
    }

    public static String getAccessTokenString() {
        return ACCESS_TOKEN_STRING;
    }

    public static String getAccessTokenStringRefreshed() {
        return ACCESS_TOKEN_STRING_REFRESHED;
    }

    public static String getUnsuccessfulResponse() {
        return UNSUCCESSFUL_RESPONSE;
    }

    public static String getSuccessfulResponse() {
        return SUCCESSFUL_RESPONSE;
    }

    public static String getCaptchaToken() {
        return CAPTCHA_TOKEN;
    }

    public static String getDeprecatedApiKey() {
        return DEPRECATED_API_KEY;
    }

    public static String getEmptyClientRepresentations() {
        return EMPTY_CLIENT_REPRESENTATIONS;
    }

    public static String getFirstName() {
        return FIRST_NAME;
    }

    public static String getLastName() {
        return LAST_NAME;
    }

    public static String getEMAIL() {
        return EMAIL;
    }

    public static String getManagerClientId() {
        return MANAGER_CLIENT_ID;
    }

    public static String getManagerClientSecret() {
        return MANAGER_CLIENT_SECRET;
    }

    public static String getRoleCreateClient() {
        return ROLE_CREATE_CLIENT;
    }

    public static String getResourceAccess() {
        return RESOURCE_ACCESS;
    }

    public static String getNewApiKey() {
        return NEW_API_KEY;
    }

    public static String getCaptchaApiKey() {
        return CAPTCHA_API_KEY;
    }

    public static String getMigrateApiKey() {
        return MIGRATE_API_KEY;
    }

    public static String getNonExistigApiKey() {
        return NON_EXISTIG_API_KEY;
    }

    public static String getNewKeycloakid() {
        return NEW_KEYCLOAKID;
    }

    public static String getTOKEN() {
        return TOKEN;
    }

    public static String getWEBSITE() {
        return WEBSITE;
    }

    public static String getSECTOR() {
        return SECTOR;
    }

    public static String getCOMPANY() {
        return COMPANY;
    }
}
