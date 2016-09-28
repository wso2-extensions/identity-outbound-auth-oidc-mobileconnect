package org.wso2.carbon.identity.authenticator.mobileconnect;

/**
 * Created by keetmalin on 8/26/16.
 */
public class MobileConnectAuthenticatorConstants {

    //Constants related to the overall mobile connect properties
    public static final String AUTHENTICATOR_NAME = "MobileConnectAuthenticator";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "Mobile Connect";
    public static final String MOBILE_CONNECT_API_KEY = "APIKey";
    public static final String MOBILE_CONNECT_API_SECRET = "APISecret";
    public static final String MOBILE_CONNECT_KEY = "MobileConnectKey";
    public static final String MOBILE_CONNECT_SECRET = "MobileConnectSecret";
    public static final String CLAIM_ID = "id";
    public static final String DEFAULT_USER_IDENTIFIER = "id";
    public static final String DISCOVERY_API_URL = "http://discovery.sandbox2.mobileconnect.io/v2/discovery";
    public static final String MOBILE_CONNECT_TOKEN_CONTENT_TYPE_VALUE = "application/x-www-form-urlencoded";
    public static final String MOBILE_CONNECT_LOGIN_TYPE = "mobileconnect";

    //Constants related to Disovery API MNC, MCC access
    public static final String DISCOVERY_IDENTIFIED_MCC = "Identified-MCC";
    public static final String DISCOVERY_IDENTIFIED_MNC = "Identified-MNC";
    public static final String DISCOVERY_IGNORE_COOKIES = "Ignore-Cookies";
    public static final String DISCOVERY_LOCAL_IP = "Local-Client-IP";
    public static final String DISCOVERY_SET_COOKIES = "Set-Cookies";

    //constants related to session management
    public static final String MOBILE_CONNECT_SESSION_DATA_KEY = "sessionDataKey";
    public static final String MOBILE_CONNECT_CONTEXT_IDENTIFIER = "contextIdentifier";
    public static final String MOBILE_CONNECT_COMMONAUTH_IDP = "idp";
    public static final String MOBILE_CONNECT_COMMONAUTH_AUTHENTICATOR = "authenticator";
    public static final String MOBILE_CONNECT_COMMONAUTH_SDK = "sessionDataKey";
    public static final String MOBILE_CONNECT_CALLBACK_URL = "https://localhost:9443/commonauth";

    //Constants related to the state of the process
    public static final String MOBILE_CONNECT_SESSION_STATE = "state";
    public static final String MOBILE_CONNECT_DISCOVERY = "discovery";
    public static final String MOBILE_CONNECT_AUTHORIZATION_ENDPOINT = "authorization_endpoint";
    public static final String MOBILE_CONNECT_TOKEN_ENDPOINT = "token_endpoint";
    public static final String MOBILE_CONNECT_USERINFO_ENDPOINT = "userinfo_endpoint";
    public static final String MOBILE_CONNECT_FLOW_STATUS = "flowStatus";

    //constants related to Discovery API Connection
    public static final String MOBILE_CONNECT_DISCOVERY_AUTHORIZATION = "Authorization";
    public static final String MOBILE_CONNECT_DISCOVERY_ACCEPT = "Accept";
    public static final String MOBILE_CONNECT_DISCOVERY_ACCEPT_VALUE = "application/xml";
    public static final String MOBILE_CONNECT_DISCOVERY_CONTENT_TYPE = "Content-Type";
    public static final String MOBILE_CONNECT_DISCOVERY_MSISDN = "MSISDN";
    public static final String MOBILE_CONNECT_DISCOVERY_REDIRECT_URL = "Redirect_URL";
    public static final String MOBILE_CONNECT_DISCOVERY_JSON_OBJECT = "response";
    public static final String MOBILE_CONNECT_USING_MOBILE_DATA = "X-Using-Mobile-Data";
    public static final String MOBILE_CONNECT_MANUAL_SELECTION = "Manually-Select";


    //constants related to the Authorization Endpoint Connection
    public static final String MOBILE_CONNECT_AUTHORIZATION_CLIENT_ID = "client_id";
    public static final String MOBILE_CONNECT_AUTHORIZATION_CLIENT_SECRET = "client_secret";
    public static final String MOBILE_CONNECT_AUTHORIZATION_RESPONSE_TYPE = "code";
    public static final String MOBILE_CONNECT_AUTHORIZATION_SCOPE = "scope";
    public static final String MOBILE_CONNECT_AUTHORIZATION_REDIRECT_URI = "redirect_uri";
    public static final String MOBILE_CONNECT_AUTHORIZATION_ACR_VALUES = "acr_values";
    public static final String MOBILE_CONNECT_AUTHORIZATION_SUBSCRIBER_ID = "subscriber_id";
    public static final String MOBILE_CONNECT_AUTHORIZATION_OPERATOR_ID = "operatorid";
    public static final String MOBILE_CONNECT_AUTHORIZATION_APIS = "apis";
    public static final String MOBILE_CONNECT_AUTHORIZATION_LINK= "link";
    public static final String MOBILE_CONNECT_AUTHORIZATION_STATE = "state";
    public static final String MOBILE_CONNECT_AUTHORIZATION_NONCE = "nonce";
    public static final String MOBILE_CONNECT_AUTHORIZATION_LOGIN_HINT = "login_hint";
    public static final String MOBILE_CONNECT_LINKS_USERINFO = "userinfo";
    public static final String MOBILE_CONNECT_LINKS_AUTHORIZATION= "authorization";
    public static final String MOBILE_CONNECT_LINKS_TOKEN= "token";

    //constants related to the Token endpoint connection
    public static final String MOBILE_CONNECT_TOKEN_AUTHORIZATION = "Authorization";
    public static final String MOBILE_CONNECT_TOKEN_CONTENT_TYPE = "Content-Type";
    public static final String MOBILE_CONNECT_TOKEN_CODE = "code";
    public static final String MOBILE_CONNECT_TOKEN_GRANT_TYPE = "grant_type";
    public static final String MOBILE_CONNECT_TOKEN_REDIRECT_URI = "redirect_uri";





}
