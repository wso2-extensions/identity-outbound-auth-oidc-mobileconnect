/*
 *  Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */

package org.wso2.carbon.identity.authenticator.mobileconnect;

/**
 * Class for Constants of the MobileConnect Federated Authenticator
 * Holds the constant string literals required for the MobileConnectAuthenticator.java Class.
 */
class MCAuthenticatorConstants {

    //constants related to the Authorization Endpoint Connection
    static final String MC_AUTHORIZATION_CLIENT_ID = "client_id";
    static final String MC_AUTHORIZATION_CLIENT_SECRET = "client_secret";
    static final String MC_AUTHORIZATION_RESPONSE_TYPE = "code";
    static final String MC_AUTHORIZATION_SCOPE = "scope";
    static final String MC_AUTHORIZATION_ACR_VALUES = "acr_values";
    static final String MC_AUTHORIZATION_SUBSCRIBER_ID = "subscriber_id";
    static final String MC_AUTHORIZATION_OPERATOR_ID = "operatorid";
    static final String MC_AUTHORIZATION_APIS = "apis";
    static final String MC_AUTHORIZATION_LINK = "link";
    static final String MC_AUTHORIZATION_NONCE = "nonce";
    static final String MC_AUTHORIZATION_LOGIN_HINT = "login_hint";
    static final String MC_LINKS_USERINFO = "userinfo";
    static final String MC_LINKS_AUTHORIZATION = "authorization";
    static final String MC_LINKS_TOKEN = "token";
    static final String MC_ENCR_MSISDN = "ENCR_MSISDN";

    //Constants related to the overall mobile connect properties
    static final String AUTHENTICATOR_NAME = "MobileConnectAuthenticator";
    static final String AUTHENTICATOR_FRIENDLY_NAME = "Mobile Connect";
    static final String MC_API_KEY = "APIKey";
    static final String MC_AUTHENTICATION_TYPE = "authenticationType";
    static final String MC_API_SECRET = "APISecret";
    static final String MC_KEY = "MobileConnectKey";
    static final String MC_SECRET = "MobileConnectSecret";
    static final String MC_LINK_REFERENCE = "rel";
    static final String DEFAULT_USER_IDENTIFIER = "sub";
    static final String DISCOVERY_API_URL = "MCDiscoveryAPIURL";
    static final String MC_LOGIN_TYPE = "mobileconnect";
    static final String MC_MOBILE_CLAIM = "mobile_claim";
    static final String MC_MOBILE_CLAIM_VALUE = "http://wso2.org/claims/mobile";
    static final String MC_MOBILE_NUMBER = "mobile_number";

    //constants related to session management
    static final String MC_CALLBACK_URL = "callbackUrl";
    static final String MC_UI_ENDPOINT_URL = "MCAuthenticationEndpointURL";

    //Constants related to the state of the process
    static final String MC_DISCOVERY_ENDPOINT = "discovery_endpoint";
    static final String MC_AUTHORIZATION_ENDPOINT = "authorization_endpoint";
    static final String MC_TOKEN_ENDPOINT = "token_endpoint";
    static final String MC_USERINFO_ENDPOINT = "userinfo_endpoint";
    static final String MC_FLOW_STATUS = "flowStatus";
    static final String MC_MCC_MNC = "mcc_mnc";
    static final String MC_OPERATOR_SELECTION_STATUS = "operatorSelectionStatus";
    static final String MC_OPERATOR_SELECTION_DONE = "done";
    static final String MC_UI_STATUS = "UI_status";
    static final String MC_UI_PROCESS_COMPLETE = "complete";
    static final String MC_ON_NET_STATUS = "on_net_status";

    //constants related to Discovery API Connection
    static final String MC_DISCOVERY_AUTHORIZATION = "Authorization";
    static final String MC_DISCOVERY_REDIRECT_URL = "Redirect_URL";
    static final String MC_DISCOVERY_JSON_OBJECT = "response";
    static final String MC_ON_NET = "on-net";
    static final String MC_SESSION_DATAKEY = "sessionDataKey";
    static final String MC_CONTEXT_IDENTIFIER = "contextIdentifier";
    static final String MC_SELECTED_MCC = "Selected-MCC";
    static final String MC_SELECTED_MNC = "Selected-MNC";
    static final String MC_MSISDN = "msisdn";

    //constants related to the Token endpoint connection
    static final String MC_TOKEN_CODE = "code";
    static final String MC_TOKEN_GRANT_TYPE = "authorization_code";
    static final String MC_TOKEN_JSON_OBJECT = "token_json_object";
    static final String MC_USER_INFO_JSON_OBJECT = "user_info_json_object";

    //calimDialectUri parameter
    static final String CLAIM_DIALECT_URI_PARAMETER = "ClaimDialectUri";
    static final String PREFIX_CLAIM_DIALECT_URI_PARAMETER = "PrefixClaimDialectUri";

    //constants related to UserInfo Endpoint
    static final String ACCESS_TOKEN = "access_token";
    static final String TOKEN_TYPE = "token_type";
    static final String ID_TOKEN = "id_token";


    //constants related to OIDC variables
    static final String OIDC_CODE = "code";
    static final String OIDC_STATE = "state";
    static final String OIDC_ERROR = "error";

}
