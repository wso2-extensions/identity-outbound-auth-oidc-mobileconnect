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

import org.apache.axiom.util.base64.Base64Utils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.utils.JSONUtils;
import org.codehaus.jettison.json.JSONArray;
import org.codehaus.jettison.json.JSONException;
import org.codehaus.jettison.json.JSONObject;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.ApplicationAuthenticatorException;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.oidc.OpenIDConnectAuthenticator;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Authenticator of Mobile Connect.
 * The MobileConnectAuthenticator class carries out the Discovery API Process and the Mobile Connect API process
 */
public class MobileConnectAuthenticator extends OpenIDConnectAuthenticator implements
        FederatedApplicationAuthenticator {

    private static final long serialVersionUID = -8755624597283931608L;
    private static Log log = LogFactory.getLog(MobileConnectAuthenticator.class);

    /**
     * Check whether the authentication or logout request can be handled by the
     * authenticator.
     */
    public boolean canHandle(HttpServletRequest request) {

        //this condition is to control the status of the UI flow
        if ((MobileConnectAuthenticatorConstants.MOBILE_CONNECT_COMPLETE).equals(request.getSession().getAttribute
                (MobileConnectAuthenticatorConstants
                        .MOBILE_CONNECT_UI_STATUS))) {
            request.getSession().setAttribute(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_UI_STATUS, "");
            return true;

        } else if ((MobileConnectAuthenticatorConstants.MOBILE_CONNECT_OPERATOR_SELECTION_DONE.
                equals(request.getSession().getAttribute(MobileConnectAuthenticatorConstants.
                        MOBILE_CONNECT_OPERATOR_SELECTION_STATUS)))) {
            //to check whetehr the operator selection process is completed
            request.getSession().setAttribute(MobileConnectAuthenticatorConstants.
                    MOBILE_CONNECT_OPERATOR_SELECTION_STATUS, "");
            return false;

        } else if (request.getParameter(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_MCC_MNC) != null) {
            //to check if the request is carrying a mcc_mnc parameter
            request.getSession().setAttribute(MobileConnectAuthenticatorConstants.
                    MOBILE_CONNECT_OPERATOR_SELECTION_STATUS, MobileConnectAuthenticatorConstants.
                    MOBILE_CONNECT_OPERATOR_SELECTION_DONE);
            return true;

        } else {
            //return false if OIDC authorization process is incomplete
            return request.getParameter(MobileConnectAuthenticatorConstants.OIDC_CODE) != null && request.getParameter
                    (MobileConnectAuthenticatorConstants.OIDC_STATE) != null
                    && MobileConnectAuthenticatorConstants.MOBILE_CONNECT_LOGIN_TYPE.equals(this.getLoginType
                    (request)) || request
                    .getParameter(MobileConnectAuthenticatorConstants.OIDC_STATE) != null
                    && request.getParameter(MobileConnectAuthenticatorConstants.OIDC_ERROR) != null;
        }

    }

    /**
     * Get the login type of the request and identify the authenticator.
     */
    private String getLoginType(HttpServletRequest request) {
        String state = request.getParameter(MobileConnectAuthenticatorConstants.OIDC_STATE);
        return state != null ? state.split(",")[1] : null;
    }


    /**
     * Initiate the Authentication request when the AuthenticatorFlowStatus is INCOMPLETE.
     */
    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context)
            throws AuthenticationFailedException {

        //retrieve the properties configured
        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
        //retrieve the authentication type for mobile connect
        String authenticationType = authenticatorProperties.get(MobileConnectAuthenticatorConstants.
                MOBILE_CONNECT_AUTHENTICATION_TYPE);

        if ((MobileConnectAuthenticatorConstants.MOBILE_CONNECT_ON_NET).equals(authenticationType)) {

            //this is null, if no such properties are defined in the IS as an IDPqq
            if (authenticatorProperties != null) {

                    context.setProperty(MobileConnectAuthenticatorConstants.
                            MOBILE_CONNECT_UI_PROMPT , "true");

                    //get the mobile connect key and secret
                    String mobileConnectKey = getMobileConnectAPIKey(authenticatorProperties);
                    String mobileConnectSecret = getMobileConnectAPISecret(authenticatorProperties);

                    //Base 64 encode the key and secret to attach as the header for URL connections
                    String userpass = mobileConnectKey + ":" + mobileConnectSecret;
                    String authorizationHeader = "Basic " + Base64Utils.
                            encode(userpass.getBytes(StandardCharsets.UTF_8));

                if ((MobileConnectAuthenticatorConstants.MOBILE_CONNECT_MCC_MNC).equals(context.getProperty
                        (MobileConnectAuthenticatorConstants.
                        MOBILE_CONNECT_FLOW_STATUS))) {

                    String kkk = request.getParameter("mcc_mnc");
                    String mcc = kkk.substring(0 , 3);
                    String mnc = kkk.substring(4);

                    String url = "https://discover.mobileconnect" +
                            ".io/gsma/v2/discovery?Identified-MCC=" + mcc + "&Identified-MNC=" + mnc +
                            "&Redirect_URL=" +
                            "https://localhost:9443/commonauth&Ignore-Cookies=true";

                    URL obj = null;
                    try {
                        obj = new URL(url);
                    } catch (MalformedURLException e) {
                        throw new AuthenticationFailedException("k");
                    }
                    HttpURLConnection connection = null;
                    try {
                        connection = (HttpURLConnection) obj.openConnection();
                    } catch (IOException e) {
                        throw new AuthenticationFailedException("k");
                    }

                    try {
                        connection.setRequestMethod("GET");
                    } catch (ProtocolException e) {
                        throw new AuthenticationFailedException("k");
                    }
                    connection.setRequestProperty(MobileConnectAuthenticatorConstants.
                                    MOBILE_CONNECT_DISCOVERY_AUTHORIZATION,
                            authorizationHeader);
                    connection.setRequestProperty(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_ACCEPT,
                            MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_ACCEPT_VALUE);
                    connection.setDoOutput(true);
                    try {

                        int responseCode = connection.getResponseCode();
                        //if 200 OK
                        if (responseCode == 200) {

                            //read the response sent by the server
                            BufferedReader reader = new BufferedReader(new InputStreamReader(connection.
                                    getInputStream(),
                                    StandardCharsets.UTF_8));
                            StringBuilder stringBuilder = new StringBuilder();
                            String line;
                            while ((line = reader.readLine()) != null) {
                                stringBuilder.append(line);
                            }
                            String responseString = stringBuilder.toString();
                            reader.close();
                            JSONObject jsonObject = new JSONObject(responseString);
                            context.setProperty(MobileConnectAuthenticatorConstants.
                                            MOBILE_CONNECT_DISCOVERY_JSON_OBJECT,
                                    jsonObject);
                            context.setProperty(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_FLOW_STATUS,
                                    MobileConnectAuthenticatorConstants.MOBILE_CONNECT_AUTHORIZATION_ENDPOINT);
                            log.info("MSISDN is valid. Discovery Endpoint authorization successful");


                        } else if (responseCode == 302) {
                            //if 302, move temporarily
                            String redirectUrl = connection.getHeaderField("location");
                            response.sendRedirect(redirectUrl);
                            context.setProperty(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_FLOW_STATUS,
                                    MobileConnectAuthenticatorConstants.MOBILE_CONNECT_AUTHORIZATION_ENDPOINT);
                            log.info("MSISDN is invalid. Redirecting to mobile connect interface");
                        } else if (responseCode == 401) {
                            //if 401 unauthorized
                            String url2 = ConfigurationFacade.getInstance().getAuthenticationEndpointRetryURL();
                            response.sendRedirect(url2);
                            log.error("No Authorization or Bad Session");
                        } else if (responseCode == 404) {
                            //if 404, not found
                            String url2 = ConfigurationFacade.getInstance().getAuthenticationEndpointRetryURL();
                            response.sendRedirect(url2);
                            log.error("Bad MSISDN is supplied");
                        } else if (responseCode == 400) {
                            //if 400 bad request
                            String url2 = ConfigurationFacade.getInstance().getAuthenticationEndpointRetryURL();
                            response.sendRedirect(url2);
                            log.error("Bad MSISDN is supplied");
                        }
                    } catch (IOException e) {
                        throw new AuthenticationFailedException("");
                    } catch (JSONException e) {
                        throw new AuthenticationFailedException("");
                    }

                    if (MobileConnectAuthenticatorConstants.MOBILE_CONNECT_AUTHORIZATION_ENDPOINT.equals(context.
                            getProperty(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_FLOW_STATUS))) {

                        //call this method to decode the response sent from the Discovery Endpoint and connect with the
                        // authorization endpoint
                        authenticationEndpoint(context, response);
                    }


                } else {

                    //carryout the process of connecting the Discovery Endpoint for on-net Operator Selection
                    operatorSelectionProcess(authorizationHeader, context,
                            response, request);

                    //set property in context to ensure that operator selection is being carried out in the flow
                    context.setProperty(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_FLOW_STATUS,
                            MobileConnectAuthenticatorConstants.MOBILE_CONNECT_MCC_MNC);

                }




//                }



            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Error while retrieving properties. Authenticator Properties cannot be null");
                }
                throw new AuthenticationFailedException(" Authenticator Properties cannot be null");
            }

        } else if ((MobileConnectAuthenticatorConstants.MOBILE_CONNECT_OFF_NET).equals(authenticationType)) {
            if (context.getProperty(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_FLOW_STATUS) == null) {

                //retrieve the url of the UI from the Configuration Files
                String login = getAuthenticatorConfig().getParameterMap().get(MobileConnectAuthenticatorConstants
                        .MOBILE_CONNECT_UI_ENDPOINT_URL);

                String loginPage = "";
                if (StringUtils.isNotEmpty(login)) {
                    loginPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL()
                            .replace("authenticationendpoint/login.do", login);
                }
                //get query parameter from the context
                String queryParams = FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(),
                        context.getCallerSessionKey(), context.getContextIdentifier());

                //if the context is in retrying stage
                String retryParam = "";
                if (context.isRetrying()) {
                    retryParam = "&authFailure=true&authFailureMsg=login.fail.message";
                }

                try {
                    //set this status to notify the controller that the UI stage is completed
                    request.getSession().setAttribute(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_UI_STATUS,
                            MobileConnectAuthenticatorConstants.MOBILE_CONNECT_COMPLETE);
                    //redirect to the UI page
                    response.sendRedirect(response.encodeRedirectURL(loginPage +
                            ("?" + queryParams)) + "&authenticators="
                            + getName() + retryParam);
                } catch (IOException e) {
                    throw new AuthenticationFailedException("Authentication failed!", e);

                }
                context.setProperty(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_FLOW_STATUS,
                        MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_ENDPOINT);

            } else {

                //check whether the msisdn is sent by the service provider
                String msisdn = request.getParameter("msisdn");

                //retrieve the properties configured
                authenticatorProperties = context.getAuthenticatorProperties();

                //this is null, if no such properties are defined in the IS as an IDPqq
                if (authenticatorProperties != null) {

                    //MobileConnectAuthenticatorConstants.MOBILE_CONNECT_FLO
                    // W_STATUS is the property set by the IDP, to keep
                    // track of the authentication process
                    if (context.getProperty(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_FLOW_STATUS) ==
                            MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_ENDPOINT) {

                        //get the mobile connect key and secret
                        String mobileConnectKey = getMobileConnectAPIKey(authenticatorProperties);
                        String mobileConnectSecret = getMobileConnectAPISecret(authenticatorProperties);

                        //Base 64 encode the key and secret to attach as the header for URL connections
                        String userpass = mobileConnectKey + ":" + mobileConnectSecret;
                        String authorizationHeader = "Basic " + Base64Utils.
                                encode(userpass.getBytes(StandardCharsets.UTF_8));


                        try {
                            //carryout the process of connecting the Discovery Endpoint
                            discoveryEndpointConnect(authorizationHeader, msisdn, context,
                                    response, authorizationHeader);
                        } catch (JSONException e) {
                            //redirect to Log in retry URL
                            String url = ConfigurationFacade.getInstance().getAuthenticationEndpointRetryURL();
                            try {
                                response.sendRedirect(url);
                                throw new AuthenticationFailedException("Invalid JSON object returned", e);
                            } catch (IOException e1) {
                                throw new AuthenticationFailedException("response redirection failed", e1);
                            }
                        }
                    }

                    if (MobileConnectAuthenticatorConstants.MOBILE_CONNECT_AUTHORIZATION_ENDPOINT.equals(context.
                            getProperty(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_FLOW_STATUS))) {

                        //call this method to decode the response sent from the Discovery Endpoint and connect with the
                        // authorization endpoint
                        authenticationEndpoint(context, response);
                    }

                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("Error while retrieving properties. Authenticator Properties cannot be null");
                    }
                    throw new AuthenticationFailedException(" Authenticator Properties cannot be null");
                }
            }

        } else {
            throw new AuthenticationFailedException("Authentication type is not configured properly in the IS " +
                    "management console");
        }



    }

    /**
     * Call the Discovery Endpoint in On-Net Scenario.
     */
    public void operatorSelectionProcess(String authorizationHeader, AuthenticationContext context,
                                         HttpServletResponse response, HttpServletRequest request) throws
            AuthenticationFailedException {

        try {
            HttpResponse httpResponse = discoveryProcess2(authorizationHeader);
            String url = httpResponse.getHeaders("location")[0].toString().substring(10);

            String queryParams = FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(),
                    context.getCallerSessionKey(), context.getContextIdentifier());
            String subStr = queryParams.substring(queryParams
                    .indexOf("sessionDataKey" + "="));
            String sessionDK = subStr.substring(subStr.indexOf("sessionDataKey"
                    + "="), subStr.indexOf("&")).replace(("sessionDataKey" + "=")
                    , "");

            request.getSession().setAttribute("sessionDataKey", sessionDK);
            response.sendRedirect(url);

        } catch (IOException e) {
            throw new AuthenticationFailedException("l");
        }
    }

    public String getContextIdentifier(HttpServletRequest request) {
        if (request.getSession().getAttribute("contextIdentifier") == null) {
            request.getSession().setAttribute("contextIdentifier",
                    request.getParameter("sessionDataKey"));
            return (String) request.getSession().getAttribute("sessionDataKey");
        } else {
            return (String) request.getSession().getAttribute("contextIdentifier");
        }
    }

    /**
     * Process the authentication request sent by the Authorization endpoint.
     */
    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws
            AuthenticationFailedException {

        //call this method to contact the tokenEndpoint and retrieve the token
        tokenAuthenticationRequest(request, response, context);

        //get jsonString object from the context
        String jsonObject = (String) context.
                getProperty(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_USER_INFO_RESPONSE);


        JSONObject json = (JSONObject) context.
                getProperty("json");

        String msisdn = null;
        try {
            msisdn = json.getString("msisdn");
        } catch (JSONException e) {
            throw new AuthenticationFailedException("Authentication failed", e);
        }

            AuthenticatedUser authenticatedUser =
                    AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(msisdn);
            context.setSubject(authenticatedUser);

//        try {
//            buildClaims(context, jsonObject);
//        } catch (ApplicationAuthenticatorException e) {
//            throw new AuthenticationFailedException("Authentication failed", e);
//        }

    }

    /**
     * Handle the response received from the Discovery Endpoint and connect with the Authentication Endpoint.
     */
    private void authenticationEndpoint(AuthenticationContext context, HttpServletResponse response) throws
            AuthenticationFailedException {

        //retrieve the properties configured
        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();

        //decode the json object returned from the Discovery API
        JSONObject jsonObject = (JSONObject) context.
                getProperty(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_JSON_OBJECT);
        String authorizationEndpoint = "";
        String tokenEndpoint = "";
        String userinfoEndpoint = "";
        String operatoridScope = "";
        String authorizationClientId;
        String authorizationSecret;
        String subscriberId = "";

        String uiPromptStatus = (String) context.getProperty(MobileConnectAuthenticatorConstants
                .MOBILE_CONNECT_UI_PROMPT);

        try {

            JSONObject jsonResponse = jsonObject.
                    getJSONObject(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_JSON_OBJECT);
            authorizationClientId = jsonResponse.
                    getString(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_AUTHORIZATION_CLIENT_ID);
            authorizationSecret = jsonResponse.
                    getString(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_AUTHORIZATION_CLIENT_SECRET);

            if (!("true").equals(uiPromptStatus)) {
                            subscriberId = jsonObject.
                    getString(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_AUTHORIZATION_SUBSCRIBER_ID);
            }

            JSONObject apis = jsonResponse.
                    getJSONObject(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_AUTHORIZATION_APIS);
            JSONObject operatorid = apis.
                    getJSONObject(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_AUTHORIZATION_OPERATOR_ID);

            JSONArray operatoridLink = operatorid.
                    getJSONArray(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_AUTHORIZATION_LINK);

            for (int i = 0; i < operatoridLink.length(); i++) {
                String linkRef = operatoridLink.getJSONObject(i).getString("rel");
                if (MobileConnectAuthenticatorConstants.MOBILE_CONNECT_LINKS_AUTHORIZATION.equals(linkRef)) {
                    authorizationEndpoint = operatoridLink.getJSONObject(i).getString("href");
                } else if (MobileConnectAuthenticatorConstants.MOBILE_CONNECT_LINKS_TOKEN.equals(linkRef)) {
                    tokenEndpoint = operatoridLink.getJSONObject(i).getString("href");
                } else if (MobileConnectAuthenticatorConstants.MOBILE_CONNECT_LINKS_USERINFO.equals(linkRef)) {
                    userinfoEndpoint = operatoridLink.getJSONObject(i).getString("href");
                } else if (MobileConnectAuthenticatorConstants.MOBILE_CONNECT_AUTHORIZATION_SCOPE.equals(linkRef)) {
                    operatoridScope = operatoridLink.getJSONObject(i).getString("href");
                }
            }

        } catch (JSONException e) {
            //redirect to Log in retry URL
            String url = ConfigurationFacade.getInstance().getAuthenticationEndpointRetryURL();
            try {
                response.sendRedirect(url);
                throw new AuthenticationFailedException("Invalid JSON object returned " +
                        "from the Discovery Server", e);
            } catch (IOException e1) {
                throw new AuthenticationFailedException("response redirection failed.", e1);
            }
        }

        //get scope from authentication Properties or from the response in the Discovery API
        String scope = getMobileConnectScope(authenticatorProperties, operatoridScope);
        //get acr values from the authentication properties
        String acrValues = authenticatorProperties.
                get(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_AUTHORIZATION_ACR_VALUES);
        //retrieve current state
        String state = context.getContextIdentifier() + "," +
                MobileConnectAuthenticatorConstants.MOBILE_CONNECT_LOGIN_TYPE;

        //create oAuthClientrequest to contact the Authorization Endpooint
        try {
            OAuthClientRequest oAuthClientRequest = null;

            if (!("true").equals(uiPromptStatus)) {

                oAuthClientRequest = OAuthClientRequest
                        .authorizationLocation(authorizationEndpoint)
                        .setClientId(authorizationClientId)
                        .setRedirectURI("https://localhost:9443/commonauth")
                        .setResponseType(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_AUTHORIZATION_RESPONSE_TYPE)
                        .setScope(scope)
                        .setState(state)
                        .setParameter(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_AUTHORIZATION_ACR_VALUES,
                                acrValues)
                        .setParameter(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_AUTHORIZATION_NONCE, state)
                    .setParameter(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_AUTHORIZATION_LOGIN_HINT,
                            "ENCR_MSISDN:" + subscriberId)
                        .buildQueryMessage();

            } else {

                oAuthClientRequest = OAuthClientRequest
                        .authorizationLocation(authorizationEndpoint)
                        .setClientId(authorizationClientId)
                        .setRedirectURI("https://localhost:9443/commonauth")
                        .setResponseType(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_AUTHORIZATION_RESPONSE_TYPE)
                        .setScope(scope)
                        .setState(state)
                        .setParameter(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_AUTHORIZATION_ACR_VALUES,
                                acrValues)
                        .setParameter(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_AUTHORIZATION_NONCE, state)
                        .buildQueryMessage();

            }


            //contact the authorization endpoint
            String url = oAuthClientRequest.getLocationUri();
            response.sendRedirect(url);

            //set the context values to be used in the rest of the flow
            context.setProperty(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_FLOW_STATUS,
                    MobileConnectAuthenticatorConstants.MOBILE_CONNECT_TOKEN_ENDPOINT);
            context.setProperty(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_TOKEN_ENDPOINT, tokenEndpoint);
            context.setProperty(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_USERINFO_ENDPOINT, userinfoEndpoint);
            context.setProperty(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_AUTHORIZATION_CLIENT_ID,
                    authorizationClientId);
            context.setProperty(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_AUTHORIZATION_CLIENT_SECRET,
                    authorizationSecret);

        } catch (OAuthSystemException | IOException e) {
            throw new AuthenticationFailedException("response redirection failed", e);
        }
    }


    /**
     * Carry out the discovery API endpoint connections.
     */
    private void discoveryEndpointConnect(String basicAuth, String msisdn,
                                          AuthenticationContext context,
                                          HttpServletResponse response , String authorizationHeader)
            throws JSONException,
            AuthenticationFailedException {


        try {


            //call this method to retrieve a HttpURLConnection object
            HttpURLConnection connection = discoveryProcess(basicAuth, msisdn);

            //check the responseCode of the HttpURLConnection
            int responseCode = connection.getResponseCode();

            //if 200 OK
            if (responseCode == 200) {



                //read the response sent by the server
                BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream(),
                        StandardCharsets.UTF_8));
                StringBuilder stringBuilder = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    stringBuilder.append(line);
                }
                String responseString = stringBuilder.toString();
                reader.close();
                JSONObject jsonObject = new JSONObject(responseString);
                context.setProperty(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_JSON_OBJECT,
                        jsonObject);
                context.setProperty(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_FLOW_STATUS,
                        MobileConnectAuthenticatorConstants.MOBILE_CONNECT_AUTHORIZATION_ENDPOINT);
                log.info("MSISDN is valid. Discovery Endpoint authorization successful");


            } else if (responseCode == 302) {
                //if 302, move temporarily
                String redirectUrl = connection.getHeaderField("location");
                response.sendRedirect(redirectUrl);
                context.setProperty(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_FLOW_STATUS,
                        MobileConnectAuthenticatorConstants.MOBILE_CONNECT_AUTHORIZATION_ENDPOINT);
                log.info("MSISDN is invalid. Redirecting to mobile connect interface");
            } else if (responseCode == 401) {
                //if 401 unauthorized
                String url = ConfigurationFacade.getInstance().getAuthenticationEndpointRetryURL();
                response.sendRedirect(url);
                log.error("No Authorization or Bad Session");
            } else if (responseCode == 404) {
                //if 404, not found
                String url = ConfigurationFacade.getInstance().getAuthenticationEndpointRetryURL();
                response.sendRedirect(url);
                log.error("Bad MSISDN is supplied");
            } else if (responseCode == 400) {
                //if 400 bad request
                String url = ConfigurationFacade.getInstance().getAuthenticationEndpointRetryURL();
                response.sendRedirect(url);
                log.error("Bad MSISDN is supplied");
            }
        } catch (IOException e) {
            throw new AuthenticationFailedException("response redirection failed", e);
        }


    }


    /**
     * Return the mobile connect key from configuration files or UI.
     */
    private String getMobileConnectAPIKey(Map<String, String> authenticatorProperties) throws
            AuthenticationFailedException {

        //retrieve mobile connect key from the configuration file of IS
        String mobileConnectKey = getAuthenticatorConfig().getParameterMap().
                get(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_KEY);

        if (StringUtils.isNotEmpty(mobileConnectKey)) {
            return mobileConnectKey;
        } else if (StringUtils.isNotEmpty(authenticatorProperties.
                get(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_API_KEY))) {
            //retrieve the mobile connect key from the IS user interface
            return authenticatorProperties.get(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_API_KEY);
        } else {

            //if both the configuration files and UI key values are null
            throw new AuthenticationFailedException("MobileConnect Key is not configured");
        }

    }


    /**
     * Return the mobile connect scope from UI or Discovery API response.
     */
    private String getMobileConnectScope(Map<String, String> authenticatorProperties, String operatoridScope) throws
            AuthenticationFailedException {

        //retrieve mobile connect scope from the UI
        if (StringUtils.isNotEmpty(authenticatorProperties.
                get(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_AUTHORIZATION_SCOPE))) {
            return authenticatorProperties.get(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_AUTHORIZATION_SCOPE);
        } else if (StringUtils.isNotEmpty(operatoridScope)) {
            //retrieve the mobile connect scope from the discovery response
            return operatoridScope;
        } else {
            //if both the UI scope and Discovery response scope values are null
            throw new AuthenticationFailedException("MobileConnect Scope is not configured correctly");
        }

    }


    /**
     * Return the mobile connect secret from configuration files or UI.
     */
    private String getMobileConnectAPISecret(Map<String, String> authenticatorProperties) throws
            AuthenticationFailedException {

        //retrieve mobile connect secret from the configuration file of IS
        String mobileConnectSecret = getAuthenticatorConfig().getParameterMap().
                get(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_SECRET);
        if (StringUtils.isNotEmpty(mobileConnectSecret)) {
            return mobileConnectSecret;
        } else if (StringUtils.isNotEmpty(authenticatorProperties.
                get(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_API_SECRET))) {
            //retrieve the mobile connect secret from the IS user interface
            return authenticatorProperties.get(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_API_SECRET);
        } else {
            //if both the configuration files and UI secret values are null
            throw new AuthenticationFailedException("MobileConnect Secret is not configured");
        }

    }


    /**
     * Process the response of the Discovery and Mobile Connect API and contact the Token Endpoint.
     */
    private void tokenAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                            AuthenticationContext context)
            throws AuthenticationFailedException {


        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();

        //get the following values from the context of the flow
        String tokenEndpoint = (String) context.
                getProperty(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_TOKEN_ENDPOINT);
        String authorizationClientId = (String) context.
                getProperty(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_AUTHORIZATION_CLIENT_ID);
        String authorizationSecret = (String) context.
                getProperty(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_AUTHORIZATION_CLIENT_SECRET);

        try {

            String redirectURL = getCallbackUrl(authenticatorProperties);
            String code = request.getParameter(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_TOKEN_CODE);

            //Base 64 encode the key and secret to attach as the header for URL connections
            String userpass = authorizationClientId + ":" + authorizationSecret;
            String authorizationHeader = "Basic " + Base64Utils.encode(userpass.getBytes(StandardCharsets.UTF_8));

            //url with query parameters for TokenEndpoint API call
            String url = tokenEndpoint + "?" + "code=" + code + "&grant_type=" +
                    MobileConnectAuthenticatorConstants.MOBILE_CONNECT_TOKEN_GRANT_TYPE + "&redirect_uri=" +
                    redirectURL;

            URL obj = new URL(url);
            HttpURLConnection connection = (HttpURLConnection) obj.openConnection();

            connection.setRequestMethod("POST");
            connection.setRequestProperty(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_AUTHORIZATION,
                    authorizationHeader);
            connection.setRequestProperty(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_TOKEN_CONTENT_TYPE,
                    MobileConnectAuthenticatorConstants.MOBILE_CONNECT_TOKEN_CONTENT_TYPE_VALUE);

            //if the connection is unauthorized
            if (connection.getResponseCode() == 401 || connection.getResponseCode() == 400) {
                String retryURL = ConfigurationFacade.getInstance().getAuthenticationEndpointRetryURL();
                try {
                    response.sendRedirect(retryURL);
                    throw new AuthenticationFailedException("Invalid Token. Authentication failed");
                } catch (IOException e1) {
                    throw new AuthenticationFailedException("response redirection failed", e1);
                }

                //if connection is authorized
            } else {
                //read the response sent by the server
                BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream(),
                        StandardCharsets.UTF_8));
                StringBuilder stringBuilder = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    stringBuilder.append(line);
                }
                String responseString = stringBuilder.toString();
                reader.close();

                //create json object
                JSONObject jsonObject = new JSONObject(responseString);
                context.setProperty(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_TOKEN_JSON_OBJECT,
                        jsonObject);

                log.info("Token Endpoint API call successful");

                //call the userinfoAuthenticationRequest to retrive user information
                userInfoAuthenticationRequest(context);
            }


        } catch (IOException | JSONException e) {
            throw new AuthenticationFailedException("Authentication failed", e);
        }


    }

    /**
     * Access the userinfo Endpoint and using the access_token.
     */
    private void userInfoAuthenticationRequest(AuthenticationContext context) throws
            AuthenticationFailedException, IOException {

        BufferedReader bufferedReader = null;
        StringBuilder stringBuilder;
        try {

            //retrieve the userinfo endpoint url from the Context
            String url = getUserInfoEndpointURL(context);

            JSONObject jsonObject = (JSONObject) context.
                    getProperty(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_TOKEN_JSON_OBJECT);

            //decode JSON Object
            String accessToken = jsonObject.getString("access_token");
            String tokenType = jsonObject.getString("token_type");
            String idToken = jsonObject.getString("id_token");

            //add query parameters
            url = url + "&access_token=" + accessToken + "&token_type=" + tokenType + "&id_token=" + idToken;

            HttpGet httpGet = new HttpGet(url);
            String tokenValue = "Bearer " + accessToken;

            //add header values required
            httpGet.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_AUTHORIZATION, tokenValue);

            //connect to the user info endpoint
            HttpResponse urlResponse = connectURL_get(httpGet);

            bufferedReader = new BufferedReader(new InputStreamReader(urlResponse.getEntity().getContent(),
                    StandardCharsets.UTF_8));

            stringBuilder = new StringBuilder();
            String line;
            while ((line = bufferedReader.readLine()) != null) {
                stringBuilder.append(line).append("\n");
            }
            //this json String includes the mobile number.
            String jsonString = stringBuilder.toString();
            JSONObject jsonUserInfo = new JSONObject(jsonString);

            String msisdn = jsonUserInfo.getString("msisdn");

//            context.setProperty(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_USER_INFO_RESPONSE,
//                    "{'fullName' : '" + msisdn + "'} ");
            context.setProperty("json" , jsonUserInfo);
//            AuthenticatedUser authenticatedUser =
//                    AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(msisdn);
//            context.setSubject(authenticatedUser);

        } catch (IOException | JSONException e) {
            throw new AuthenticationFailedException("Authentication Error when contacting the userinfo endpoint", e);
            } finally {
            if (bufferedReader != null) {
                bufferedReader.close();
            }

        }

    }

    /**
     * Get user info endpoint URL.
     */
    private String getUserInfoEndpointURL(AuthenticationContext context) {

        String url = (String) context.
                getProperty(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_USERINFO_ENDPOINT);
        if (StringUtils.isNotEmpty(url)) {
            return url;
        } else {
            //this is mainly for Indian Networks
            return "https://india.mconnect.wso2telco.com/oauth2/userinfo?schema=openid";
        }
    }


    /**
     * Execute the URL Get request.
     */
    private HttpResponse connectURL_get(HttpGet request)
            throws IOException {

//        HttpParams params = new BasicHttpParams();
//        params.setParameter("http.protocol.handle-redirects", false);
//        request.setParams(params);

//        HttpParams params = request.getParams();
//        params.setParameter(ClientPNames.HANDLE_REDIRECTS, Boolean.FALSE);
//        request.setParams(params);
        //execute the HttpGet request and return a HttpResponse
        CloseableHttpClient client = HttpClientBuilder.create().disableRedirectHandling().build();

        return client.execute(request);

    }

    public HttpResponse discoveryProcess2(String authorizationHeader) throws IOException {
        String url = MobileConnectAuthenticatorConstants.DISCOVERY_API_URL + "?" +
                MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_REDIRECT_URL + "=" +
                MobileConnectAuthenticatorConstants.MOBILE_CONNECT_CALLBACK_URL;

//        //body parameters for the API call
//        String data = "MSISDN=" + msisdn;
//
//        URL obj = new URL(url);
//        HttpURLConnection connection = (HttpURLConnection) obj.openConnection();
//
//        connection.setRequestMethod("GET");
//        connection.setRequestProperty(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_AUTHORIZATION,
//                authorizationHeader);
//        connection.setRequestProperty(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_ACCEPT,
//                MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_ACCEPT_VALUE);
//        connection.setDoOutput(true);

//        //write data to the body of the connection
//        DataOutputStream outputStream = new DataOutputStream(connection.getOutputStream());
//        outputStream.writeBytes(data);
//        outputStream.close();

        HttpGet httpGet = new HttpGet(url);

        //add header values required
        httpGet.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_AUTHORIZATION,
                authorizationHeader);
        httpGet.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_ACCEPT,
                MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_ACCEPT_VALUE);

        //connect to the user info endpoint
        HttpResponse urlResponse = connectURL_get(httpGet);
//        BufferedReader br = new BufferedReader(new InputStreamReader(urlResponse.getEntity().getContent()));
//        String line;
//        while ((line = br.readLine()) != null) {
//            log.info(line);
//        }

        return urlResponse;
    }

    /**
     * msisdn based Discovery (Developer app uses Discovery API to send msisdn).
     */
    private HttpURLConnection discoveryProcess(String authorizationHeader, String msisdn)
            throws IOException {


        String url = MobileConnectAuthenticatorConstants.DISCOVERY_API_URL + "?" +
                MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_REDIRECT_URL + "=" +
                MobileConnectAuthenticatorConstants.MOBILE_CONNECT_CALLBACK_URL;

        //body parameters for the API call
        String data = "MSISDN=" + msisdn;

        URL obj = new URL(url);
        HttpURLConnection connection = (HttpURLConnection) obj.openConnection();

        connection.setRequestMethod("POST");
        connection.setRequestProperty(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_AUTHORIZATION,
                authorizationHeader);
        connection.setRequestProperty(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_ACCEPT,
                MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_ACCEPT_VALUE);
        connection.setDoOutput(true);

        //write data to the body of the connection
        DataOutputStream outputStream = new DataOutputStream(connection.getOutputStream());
        outputStream.writeBytes(data);
        outputStream.close();

        return connection;


//        String url = MobileConnectAuthenticatorConstants.DISCOVERY_API_URL + "?" +
//                MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_REDIRECT_URL + "=" +
//                MobileConnectAuthenticatorConstants.MOBILE_CONNECT_CALLBACK_URL;
//
////        //body parameters for the API call
////        String data = "MSISDN=" + msisdn;
////
////        URL obj = new URL(url);
////        HttpURLConnection connection = (HttpURLConnection) obj.openConnection();
////
////        connection.setRequestMethod("GET");
////        connection.setRequestProperty(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_AUTHORIZATION,
////                authorizationHeader);
////        connection.setRequestProperty(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_ACCEPT,
////                MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_ACCEPT_VALUE);
////        connection.setDoOutput(true);
//
////        //write data to the body of the connection
////        DataOutputStream outputStream = new DataOutputStream(connection.getOutputStream());
////        outputStream.writeBytes(data);
////        outputStream.close();
//
//        HttpGet httpGet = new HttpGet(url);
//
//        //add header values required
//        httpGet.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_AUTHORIZATION,
//                authorizationHeader);
//        httpGet.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_ACCEPT,
//                MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_ACCEPT_VALUE);
//
//        //connect to the user info endpoint
//        HttpResponse urlResponse = connectURL_get(httpGet);
////        BufferedReader br = new BufferedReader(new InputStreamReader(urlResponse.getEntity().getContent()));
////        String line;
////        while ((line = br.readLine()) != null) {
////            log.info(line);
////        }
//
//        return urlResponse;

    }


    /**
     * Build the claims required to follow up the process.
     */
    private void buildClaims(AuthenticationContext context, String jsonObject)
            throws ApplicationAuthenticatorException {

        Map<String, Object> userClaims;
        userClaims = JSONUtils.parseJSON(jsonObject);
        if (userClaims != null) {
            Map<ClaimMapping, String> claims = new HashMap<>();
            for (Map.Entry<String, Object> entry : userClaims.entrySet()) {
                claims.put(ClaimMapping.build(entry.getKey(), entry.getKey(), null,
                        false), entry.getValue().toString());
                if (log.isDebugEnabled() &&
                        IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.USER_CLAIMS)) {
                    log.debug("Adding claim mapping : " + entry.getKey() + " <> " + entry.getKey() + " : "
                            + entry.getValue());
                }
            }
            if (StringUtils.isBlank(context.getExternalIdP().getIdentityProvider().getClaimConfig().
                    getUserClaimURI())) {
                context.getExternalIdP().getIdentityProvider().getClaimConfig().setUserClaimURI
                        (MobileConnectAuthenticatorConstants.CLAIM_ID);
            }
            String subjectFromClaims = FrameworkUtils.getFederatedSubjectFromClaims(
                    context.getExternalIdP().getIdentityProvider(), claims);
            if (subjectFromClaims != null && !subjectFromClaims.isEmpty()) {
                AuthenticatedUser authenticatedUser =
                        AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(subjectFromClaims);
                context.setSubject(authenticatedUser);
            } else {
                setSubject(context, userClaims);
            }
            context.getSubject().setUserAttributes(claims);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Decoded json object is null");
            }
            throw new ApplicationAuthenticatorException("Decoded json object is null");
        }
    }

    /**
     * Set the subject of the Authenticator in the context.
     */
    private void setSubject(AuthenticationContext context, Map<String, Object> jsonObject)
            throws ApplicationAuthenticatorException {

        String authenticatedUserId = String.valueOf(jsonObject.
                get(MobileConnectAuthenticatorConstants.DEFAULT_USER_IDENTIFIER));

        if (log.isDebugEnabled()) {
            log.debug("The subject claim that you have selected is null. The default subject claim " +
                    authenticatedUserId + " has been set");
        }
        if (StringUtils.isEmpty(authenticatedUserId)) {
            throw new ApplicationAuthenticatorException("Authenticated user identifier is empty");
        }
        AuthenticatedUser authenticatedUser =
                AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(authenticatedUserId);

        context.setSubject(authenticatedUser);
    }

    /**
     * Get the Friendly Name of the Authenticator.
     */
    @Override
    public String getFriendlyName() {
        return MobileConnectAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    /**
     * Get the Name of the Authenticator.
     */
    @Override
    public String getName() {
        return MobileConnectAuthenticatorConstants.AUTHENTICATOR_NAME;
    }

    /**
     * Get the CallBackURL.
     */
    @Override
    protected String getCallbackUrl(Map<String, String> authenticatorProperties) {

        if (StringUtils.isNotEmpty(authenticatorProperties.get(IdentityApplicationConstants.OAuth2.CALLBACK_URL))) {
            return authenticatorProperties.get(IdentityApplicationConstants.OAuth2.CALLBACK_URL);
        }
        return MobileConnectAuthenticatorConstants.MOBILE_CONNECT_CALLBACK_URL;
    }

    /**
     * Get Configuration Properties.
     */
    @Override
    public List<Property> getConfigurationProperties() {

        List<Property> configProperties = new ArrayList<>();

        //set the mobile connect Authentication type
        Property authenticationType = new Property();
        authenticationType.setName(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_AUTHENTICATION_TYPE);
        authenticationType.setDisplayName("Mobile Connect Authentication Type");
        authenticationType.setRequired(false);
        authenticationType.setValue("on-net");
        authenticationType.setDescription("Type 'on-net' or 'off-net' to use relevant authentication type");
        authenticationType.setDisplayOrder(0);
        configProperties.add(authenticationType);

        //set the mobile connect key input field
        Property mobileConnectKey = new Property();
        mobileConnectKey.setName(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_API_KEY);
        mobileConnectKey.setDisplayName("Mobile Connect Key");
        mobileConnectKey.setRequired(false);
        mobileConnectKey.setConfidential(true);
        mobileConnectKey.setDescription("Enter the Mobile Connect Key of the Mobile Connect Application Account");
        mobileConnectKey.setDisplayOrder(1);
        configProperties.add(mobileConnectKey);

        //set the mobile connect secret input field
        Property mobileConnectSecret = new Property();
        mobileConnectSecret.setName(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_API_SECRET);
        mobileConnectSecret.setDisplayName("Mobile Connect Secret");
        mobileConnectSecret.setRequired(false);
        mobileConnectSecret.setConfidential(true);
        mobileConnectSecret.setDescription("Enter the Mobile Connect Secret of the Mobile Connect Application Account");
        mobileConnectSecret.setDisplayOrder(2);
        configProperties.add(mobileConnectSecret);

        //set the mobile connect scope input field
        Property mobileConnectScope = new Property();
        mobileConnectScope.setName(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_AUTHORIZATION_SCOPE);
        mobileConnectScope.setDisplayName("Mobile Connect Scope");
        mobileConnectScope.setRequired(true);
        mobileConnectScope.setValue("openid");
        mobileConnectScope.setDescription("Enter the Mobile Connect Scope Required");
        mobileConnectScope.setDisplayOrder(3);
        configProperties.add(mobileConnectScope);

        //set the mobile connect arc values
        Property mobileConnectAcrValues = new Property();
        mobileConnectAcrValues.setName(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_AUTHORIZATION_ACR_VALUES);
        mobileConnectAcrValues.setDisplayName("Mobile Connect ACR Values");
        mobileConnectAcrValues.setRequired(true);
        mobileConnectAcrValues.setValue("2");
        mobileConnectAcrValues.setDescription("Enter the Mobile Connect ACR Values required");
        mobileConnectAcrValues.setDisplayOrder(4);
        configProperties.add(mobileConnectAcrValues);

        return configProperties;
    }
}
