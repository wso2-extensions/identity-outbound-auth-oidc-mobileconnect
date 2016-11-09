/*
 *  Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
class MobileConnectAuthenticatorConstants {

    //constants related to the Authorization Endpoint Connection
    static final String MOBILE_CONNECT_AUTHORIZATION_CLIENT_ID = "client_id";
    static final String MOBILE_CONNECT_AUTHORIZATION_CLIENT_SECRET = "client_secret";
    static final String MOBILE_CONNECT_AUTHORIZATION_RESPONSE_TYPE = "code";
    static final String MOBILE_CONNECT_AUTHORIZATION_SCOPE = "scope";
    static final String MOBILE_CONNECT_AUTHORIZATION_ACR_VALUES = "acr_values";
    static final String MOBILE_CONNECT_AUTHORIZATION_SUBSCRIBER_ID = "subscriber_id";
    static final String MOBILE_CONNECT_AUTHORIZATION_OPERATOR_ID = "operatorid";
    static final String MOBILE_CONNECT_AUTHORIZATION_APIS = "apis";
    static final String MOBILE_CONNECT_AUTHORIZATION_LINK = "link";
    static final String MOBILE_CONNECT_AUTHORIZATION_NONCE = "nonce";
    static final String MOBILE_CONNECT_AUTHORIZATION_LOGIN_HINT = "login_hint";
    static final String MOBILE_CONNECT_LINKS_USERINFO = "userinfo";
    static final String MOBILE_CONNECT_LINKS_AUTHORIZATION = "authorization";
    static final String MOBILE_CONNECT_LINKS_TOKEN = "token";

    //Constants related to the overall mobile connect properties
    static final String AUTHENTICATOR_NAME = "MobileConnectAuthenticator";
    static final String AUTHENTICATOR_FRIENDLY_NAME = "Mobile Connect";
    static final String MOBILE_CONNECT_API_KEY = "APIKey";
    static final String MOBILE_CONNECT_AUTHENTICATION_TYPE = "authenticationType";
    static final String MOBILE_CONNECT_MSISDN_UI = "msisdn_ui_check";
    static final String MOBILE_CONNECT_API_SECRET = "APISecret";
    static final String MOBILE_CONNECT_KEY = "MobileConnectKey";
    static final String MOBILE_CONNECT_SECRET = "MobileConnectSecret";
    static final String CLAIM_ID = "id";
    static final String DEFAULT_USER_IDENTIFIER = "id";
    static final String DISCOVERY_API_URL = "https://discover.mobileconnect.io/gsma/v2/discovery/";
    static final String MOBILE_CONNECT_TOKEN_CONTENT_TYPE_VALUE = "application/x-www-form-urlencoded";
    static final String MOBILE_CONNECT_LOGIN_TYPE = "mobileconnect";

    //constants related to session management
    static final String MOBILE_CONNECT_CALLBACK_URL = "https://localhost:9443/commonauth";
    static final String MOBILE_CONNECT_UI_ENDPOINT_URL = "MCAuthenticationEndpointURL";

    //Constants related to the state of the process
    static final String MOBILE_CONNECT_DISCOVERY_ENDPOINT = "discovery_endpoint";
    static final String MOBILE_CONNECT_AUTHORIZATION_ENDPOINT = "authorization_endpoint";
    static final String MOBILE_CONNECT_TOKEN_ENDPOINT = "token_endpoint";
    static final String MOBILE_CONNECT_USERINFO_ENDPOINT = "userinfo_endpoint";
    static final String MOBILE_CONNECT_FLOW_STATUS = "flowStatus";
    static final String MOBILE_CONNECT_MCC_MNC = "mcc_mnc";
    static final String MOBILE_CONNECT_OPERATOR_SELECTION_STATUS = "operatorSelectionStatus";
    static final String MOBILE_CONNECT_OPERATOR_SELECTION_DONE = "done";
    static final String MOBILE_CONNECT_UI_STATUS = "UI_status";
    static final String MOBILE_CONNECT_COMPLETE = "complete";
    static final String MOBILE_CONNECT_UI_PROMPT = "ui_prompt";

    //constants related to Discovery API Connection
    static final String MOBILE_CONNECT_DISCOVERY_AUTHORIZATION = "Authorization";
    static final String MOBILE_CONNECT_DISCOVERY_ACCEPT = "Accept";
    static final String MOBILE_CONNECT_DISCOVERY_ACCEPT_VALUE = "application/xml";
    static final String MOBILE_CONNECT_DISCOVERY_REDIRECT_URL = "Redirect_URL";
    static final String MOBILE_CONNECT_DISCOVERY_JSON_OBJECT = "response";
    static final String MOBILE_CONNECT_ON_NET = "on-net";
    static final String MOBILE_CONNECT_OFF_NET = "off-net";

    //constants related to the Token endpoint connection
    static final String MOBILE_CONNECT_TOKEN_CONTENT_TYPE = "Content-Type";
    static final String MOBILE_CONNECT_TOKEN_CODE = "code";
    static final String MOBILE_CONNECT_USER_INFO_RESPONSE = "jsonString";
    static final String MOBILE_CONNECT_TOKEN_GRANT_TYPE = "authorization_code";
    static final String MOBILE_CONNECT_TOKEN_JSON_OBJECT = "token_json_object";

    //constants related to OIDC variables
    static final String OIDC_CODE = "code";
    static final String OIDC_STATE = "state";
    static final String OIDC_ERROR = "error";


}
