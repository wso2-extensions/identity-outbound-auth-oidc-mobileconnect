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

import org.apache.axiom.util.base64.Base64Utils;
import org.apache.commons.httpclient.HttpStatus;
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
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.ApplicationAuthenticatorException;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.oidc.OpenIDConnectAuthenticator;
import org.wso2.carbon.identity.application.common.model.ClaimConfig;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.HttpMethod;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;



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
        if ((MCAuthenticatorConstants.MC_UI_PROCESS_COMPLETE).equals(request.getSession().
                getAttribute(MCAuthenticatorConstants
                        .MC_UI_STATUS))) {
            request.getSession().setAttribute(MCAuthenticatorConstants.MC_UI_STATUS, "");
            return true;

        } else if ((MCAuthenticatorConstants.MC_OPERATOR_SELECTION_DONE.
                equals(request.getSession().getAttribute(MCAuthenticatorConstants.
                        MC_OPERATOR_SELECTION_STATUS)))) {
            //to check whether the operator selection process is completed
            request.getSession().setAttribute(MCAuthenticatorConstants.
                    MC_OPERATOR_SELECTION_STATUS, "");
            return false;

        } else if (request.getParameter(MCAuthenticatorConstants.MC_MCC_MNC) != null) {
            //to check if the request is carrying a mcc_mnc parameter
            request.getSession().setAttribute(MCAuthenticatorConstants.
                    MC_OPERATOR_SELECTION_STATUS, MCAuthenticatorConstants.
                    MC_OPERATOR_SELECTION_DONE);
            return true;

        } else {
            //return false if OIDC authorization process is incomplete
            return request.getParameter(MCAuthenticatorConstants.OIDC_CODE) != null && request.getParameter
                    (MCAuthenticatorConstants.OIDC_STATE) != null
                    && MCAuthenticatorConstants.MC_LOGIN_TYPE.equals(this.getLoginType
                    (request)) || request.getParameter(MCAuthenticatorConstants.OIDC_ERROR) != null;
        }

    }

    /**
     * Get the login type of the request and identify the authenticator.
     */
    private String getLoginType(HttpServletRequest request) {
        String state = request.getParameter(MCAuthenticatorConstants.OIDC_STATE);
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
        String authenticationType = authenticatorProperties.get(MCAuthenticatorConstants.
                MC_AUTHENTICATION_TYPE);


        //this will store the mobile number which is being used in the flow
        String msisdn = null;

        //check whether the process is multi-step authentication
        if (context.getSequenceConfig().getStepMap().size() > 1) {

            //get subject details from the Authentication provided before
            AuthenticatedUser authenticatedUser = getAuthenticatedUser(context);


            if (authenticatedUser != null) {

                //get UserRealm
                UserRealm userRealm = getUserRealm(authenticatedUser.getTenantDomain());
                //Get Tenant Aware Username
                if (userRealm != null) {
                    try {

                        //retrieve username from the user stores
                        msisdn = userRealm.getUserStoreManager()
                                .getUserClaimValue(authenticatedUser.getUserStoreDomain() + "/" + authenticatedUser.
                                                getUserName(),
                                        authenticatorProperties.
                                                get(MCAuthenticatorConstants.MC_MOBILE_CLAIM), null);

                        if (StringUtils.isNotEmpty(msisdn)) {
                            //set the mobile number in the context
                            context.setProperty(MCAuthenticatorConstants.
                                    MC_MOBILE_NUMBER, msisdn);
                            //change the flow of authentication directly Discovery Endpoint
                            context.setProperty(MCAuthenticatorConstants.MC_FLOW_STATUS,
                                    MCAuthenticatorConstants.MC_DISCOVERY_ENDPOINT);
                        } else {
                            if (log.isDebugEnabled()) {
                                log.debug("msisdn is empty during initiate Authentication Request");
                            }
                        }

                    } catch (UserStoreException e) {
                        throw new AuthenticationFailedException("Cannot find the user claim for mobile "
                                + e.getMessage(), e);
                    }
                }
            }
        }

        //If the enforce type is on-net & that the msisdn is null
        if ((MCAuthenticatorConstants.MC_ON_NET).equals(authenticationType) &&
                StringUtils.isEmpty(msisdn)) {

            //let the context know that the system is enforcing on-net
            context.setProperty(MCAuthenticatorConstants.
                    MC_ON_NET_STATUS, "true");

            //get encoded authorization header
            String authorizationHeader = getAuthorizationHeader(authenticatorProperties);

            //check whether the flow status has already discovered the mcc and mnc
            if ((MCAuthenticatorConstants.MC_MCC_MNC).equals(context.getProperty
                    (MCAuthenticatorConstants.
                            MC_FLOW_STATUS))) {

                HttpURLConnection connection;

                try {
                    //get connection from discovery endpoint with mnc, mnc
                    connection = callDiscoveryWithMccMnc(request, authenticatorProperties,
                            authorizationHeader);

                } catch (IOException e) {
                    throw new AuthenticationFailedException("Connection to Discovery API failed", e);
                }

                  //Read contents retrieved from the Discovery Endpoint
                    discoveryEndpointRead(context, response, connection);

                //if the current flow status is in Authorization Phase
                if (MCAuthenticatorConstants.MC_AUTHORIZATION_ENDPOINT.equals(context.
                        getProperty(MCAuthenticatorConstants.MC_FLOW_STATUS))) {

                    //call this method to decode the response sent from the Discovery Endpoint and connect with the
                    // authorization endpoint
                    revokeAuthorizationEndpoint(context, request, response);
                }


            } else {

                //carryout the process of connecting the Discovery Endpoint for on-net Operator Selection
                operatorSelectionProcess(authorizationHeader, context, response, request);

                //set property in context to ensure that operator selection is being carried out in the flow
                context.setProperty(MCAuthenticatorConstants.MC_FLOW_STATUS,
                        MCAuthenticatorConstants.MC_MCC_MNC);

            }

            //execute this section if the Authentication Type is Off-Net (default is off-net)
        } else {
            if (context.getProperty(MCAuthenticatorConstants.MC_FLOW_STATUS) == null &&
                    StringUtils.isEmpty(msisdn)) {

                redirectToMobileNumberUI(request, response, context);

            } else {

                if (StringUtils.isEmpty(msisdn)) {
                    //check whether the msisdn is sent by the service provider
                    msisdn = request.getParameter(MCAuthenticatorConstants.MC_MSISDN);
                }
                //retrieve the properties configured
                authenticatorProperties = context.getAuthenticatorProperties();

                //this is null, if no such properties are defined in the IS as an IDPqq
                if (authenticatorProperties != null) {

                    //MCAuthenticatorConstants.MC_FLOW_STATUS is the property set by the IDP,
                    // to keep track of the authentication process
                    if (MCAuthenticatorConstants.MC_DISCOVERY_ENDPOINT.equals(context.getProperty
                            (MCAuthenticatorConstants.MC_FLOW_STATUS))) {

                        //get encoded authorization header
                        String authorizationHeader = getAuthorizationHeader(authenticatorProperties);

                        try {

                            String callbackURL = getCallbackUrl(authenticatorProperties);

                            if (StringUtils.isBlank(callbackURL)) {
                                callbackURL = IdentityUtil.getServerURL(FrameworkConstants.COMMONAUTH,
                                        true, true);
                            }

                            //call this method to retrieve a HttpURLConnection object
                            HttpURLConnection connection = msisdnBasedDiscoveryProcess(authorizationHeader,
                                    msisdn, callbackURL);

                            //carryout the process of connecting the Discovery Endpoint
                            discoveryEndpointRead(context, response, connection);

                        } catch (IOException e) {
                            throw new AuthenticationFailedException("connection to Discovery Endpoint failed", e);
                        }

                        //call this method to decode the response sent from the Discovery Endpoint and connect with the
                        // authorization endpoint
                        revokeAuthorizationEndpoint(context, request, response);
                    }

                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("Error while retrieving properties. Authenticator Properties cannot be null");
                    }
                    throw new AuthenticationFailedException(" Authenticator Properties cannot be null");
                }
            }

        }
    }

    /**
     * Get the username of the logged in User.
     */
    private AuthenticatedUser getAuthenticatedUser(AuthenticationContext context) {
        AuthenticatedUser authenticatedUser = null;
        for (Integer stepMap : context.getSequenceConfig().getStepMap().keySet()) {
            if (context.getSequenceConfig().getStepMap().get(stepMap).getAuthenticatedUser() != null
                    && context.getSequenceConfig().getStepMap().get(stepMap).getAuthenticatedAutenticator()
                    .getApplicationAuthenticator() instanceof LocalApplicationAuthenticator) {
                authenticatedUser = context.getSequenceConfig().getStepMap().get(stepMap).getAuthenticatedUser();
                break;
            }
        }
        return authenticatedUser;
    }

    /**
     * Get the user realm of the logged in user.
     */
    private UserRealm getUserRealm(String username) throws AuthenticationFailedException {
        UserRealm userRealm;
        try {
            int tenantId = IdentityTenantUtil.getTenantId(username);
            RealmService realmService = IdentityTenantUtil.getRealmService();
            userRealm = (UserRealm) realmService.getTenantUserRealm(tenantId);
        } catch (Exception e) {
            throw new AuthenticationFailedException("Cannot find the user realm", e);
        }
        return userRealm;
    }


    /**
     * Call the discovery endpoint with mcc and mnc.
     */
    private HttpURLConnection callDiscoveryWithMccMnc(HttpServletRequest request,
                                                      Map<String, String> authenticatorProperties,
                                                      String authorizationHeader) throws IOException {

        //retrieve mcc_mnc from the request
        String mccMncValue = request.getParameter(MCAuthenticatorConstants.
                MC_MCC_MNC);
        String subscrberID = request.getParameter(MCAuthenticatorConstants.
                MC_AUTHORIZATION_SUBSCRIBER_ID);

        //retrieve mcc and mnc from above string
        String mcc = mccMncValue.substring(0, 3);
        String mnc = mccMncValue.substring(4);

        if (log.isDebugEnabled()) {
            log.debug("MCC and MNC vaues are retrived from the GSMA, the values are : " + mcc + " and : " + mnc);
        }

        //retrieve callback url
        String callbackURL = getCallbackUrl(authenticatorProperties);

        //encode query parameters
        mcc = URLEncoder.encode(mcc, String.valueOf(StandardCharsets.UTF_8));
        mnc = URLEncoder.encode(mnc, String.valueOf(StandardCharsets.UTF_8));
        callbackURL = URLEncoder.encode(callbackURL, String.valueOf(StandardCharsets.UTF_8));

        //prepare queryParameters
        String queryParameters =  MCAuthenticatorConstants.MC_SELECTED_MCC + "=" + mcc +
                "&" + MCAuthenticatorConstants.MC_SELECTED_MNC + "=" +
                mnc +
                "&" + MCAuthenticatorConstants.MC_DISCOVERY_REDIRECT_URL + "=" +
                callbackURL;


        String discoveryAPIURL =  getAuthenticatorConfig().getParameterMap().get(MCAuthenticatorConstants
                .DISCOVERY_API_URL);

        if (StringUtils.isEmpty(discoveryAPIURL)) {
            //assigning the default URL for the discoveryAPIURL hence the URL is not added in configuration file
            discoveryAPIURL = "https://discover.mobileconnect.io/gsma/v2/discovery/";
            log.warn("Discovery API URL is not configured, hence using the default value : " + discoveryAPIURL);
        }

        //call the discovery endpoint with the mcc and mnc
        String url = discoveryAPIURL + "?" + queryParameters;


        if (log.isDebugEnabled()) {
            log.debug("Calling the discovery endpoint with the mcc and mnc and the URL is " + url);
        }


        //create URL object
        URL obj = new URL(url);
        HttpURLConnection connection = (HttpURLConnection) obj.openConnection();

        //enforce GET request method on the connection
        connection.setRequestMethod(HttpMethod.GET);
        //attach headers required to contact the Discovery API
        connection.setRequestProperty(MCAuthenticatorConstants.
                MC_DISCOVERY_AUTHORIZATION, authorizationHeader);
        connection.setRequestProperty(HttpHeaders.ACCEPT,
                MediaType.APPLICATION_XML);

        return connection;
    }


    /**
     * Gets the key and secret and returns the encoded authorization header.
     */
    private String getAuthorizationHeader(Map<String, String> authenticatorProperties) throws
            AuthenticationFailedException {

        //get the mobile connect key and secret

        String mobileConnectKey = authenticatorProperties.get(MCAuthenticatorConstants.
                MC_API_KEY);
        String mobileConnectSecret =   authenticatorProperties.get(MCAuthenticatorConstants.
                MC_API_SECRET);

        String userPass = null;


        if (StringUtils.isNotEmpty(mobileConnectKey) || StringUtils.isNotEmpty(mobileConnectSecret)) {
            userPass = mobileConnectKey + ":" + mobileConnectSecret;
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Error while retrieving properties. Authenticator Properties cannot be null");
            }

            throw new AuthenticationFailedException("MobileConnect Key or MobileConnect Secret is not configured");
        }

        //Base 64 encode the key and secret to attach as the header for URL connections
         userPass = mobileConnectKey + ":" + mobileConnectSecret;

        return "Basic " + Base64Utils.
                encode(userPass.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Prompt for Mobile Number from the IS.
     */
    private void redirectToMobileNumberUI(HttpServletRequest request, HttpServletResponse response,
                                          AuthenticationContext context) throws AuthenticationFailedException {

        //retrieve the url of the UI from the Configuration Files
        String loginEndpointUrl = getAuthenticatorConfig().getParameterMap().get(MCAuthenticatorConstants
                .MC_UI_ENDPOINT_URL);

        //default login page URL will be considered as this
        String loginPage = "mobileconnectauthenticationendpoint/mobileconnect.jsp";
        if (StringUtils.isNotEmpty(loginEndpointUrl)) {
            loginPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL()
                    .replace("authenticationendpoint/login.do", loginEndpointUrl);
        } else {
            log.warn("Mobile connect Web application Endpoint URL is not configured , hence using the default " +
                    "value : " + loginPage);
        }

        //get query parameter from the context
        String queryParams = FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(),
                context.getCallerSessionKey(), context.getContextIdentifier());

        //if the context is in retrying stage
        String retryParam = "";
        if (context.isRetrying()) {
            retryParam = "&authFailure=true&authFailureMsg=login.fail.message";
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Context is not in the in retrying stage, authentication is failing ");
            }
        }

        try {
            //set this status to notify the controller that the UI stage is completed
            request.getSession().setAttribute(MCAuthenticatorConstants.MC_UI_STATUS,
                    MCAuthenticatorConstants.MC_UI_PROCESS_COMPLETE);
            //redirect to the UI page
            response.sendRedirect(response.encodeRedirectURL(loginPage +
                    ("?" + queryParams)) + "&authenticators="
                    + getName() + retryParam);
        } catch (IOException e) {
            throw new AuthenticationFailedException("Authentication failed!", e);
        }
        context.setProperty(MCAuthenticatorConstants.MC_FLOW_STATUS,
                MCAuthenticatorConstants.MC_DISCOVERY_ENDPOINT);
    }

    /**
     * Call the Discovery Endpoint in On-Net Scenario.
     */
    private void operatorSelectionProcess(String authorizationHeader, AuthenticationContext context,
                                          HttpServletResponse response, HttpServletRequest request) throws
            AuthenticationFailedException {

        try {
            //call the Discovery API to get the redirect URL
            HttpResponse httpResponse = operatorSelectionDiscoveryCall(authorizationHeader , context);
            //get the 302 redirect URL from the headers of the HttpResponse
            String url = httpResponse.getHeaders(HttpHeaders.LOCATION)[0].
                    toString().substring(10);
            //get session data key
            String sessionDataKey = getSessionDataKey(context);

            //set Session Data Key to the request
            request.getSession().setAttribute(MCAuthenticatorConstants.
                    MC_SESSION_DATAKEY, sessionDataKey);
            //call the operator selection UI
            response.sendRedirect(url);

        } catch (IOException e) {
            throw new AuthenticationFailedException("Redirect to Operator Selection UI failed", e);
        }
    }

    /**
     * Return the Session Data Key when needed.
     */
    private String getSessionDataKey(AuthenticationContext context) {

        //create Session Data Key for the context
        String queryParams = FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(),
                context.getCallerSessionKey(), context.getContextIdentifier());
        String subStr = queryParams.substring(queryParams
                .indexOf(MCAuthenticatorConstants.MC_SESSION_DATAKEY + "="));

        return subStr.substring(subStr.indexOf(MCAuthenticatorConstants.
                MC_SESSION_DATAKEY
                + "="), subStr.indexOf("&")).replace((MCAuthenticatorConstants.
                        MC_SESSION_DATAKEY + "=")
                , "");
    }

    /**
     * Return the context identifier when needed.
     */
    public String getContextIdentifier(HttpServletRequest request) {
        if (request.getSession().getAttribute(MCAuthenticatorConstants.
                MC_CONTEXT_IDENTIFIER) == null) {
            request.getSession().setAttribute(MCAuthenticatorConstants.MC_CONTEXT_IDENTIFIER,
                    request.getParameter(MCAuthenticatorConstants.MC_SESSION_DATAKEY));
            return (String) request.getSession().getAttribute(MCAuthenticatorConstants.
                    MC_SESSION_DATAKEY);
        } else {
            return (String) request.getSession().getAttribute(MCAuthenticatorConstants.
                    MC_CONTEXT_IDENTIFIER);
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

        //get JSON object of user info endpoint from context
        JSONObject json = (JSONObject) context.
                getProperty(MCAuthenticatorConstants.MC_USER_INFO_JSON_OBJECT);

        if (json == null) {
            String url = ConfigurationFacade.getInstance().getAuthenticationEndpointRetryURL();
            try {
                response.sendRedirect(url);
            } catch (IOException e) {
                throw new AuthenticationFailedException("Authentication failed , received response is empty");
            }
        } else {
            try {
                buildClaims(context, json.toString());
            } catch (ApplicationAuthenticatorException e) {
                throw new AuthenticationFailedException("Authentication failed", e);
            }
        }

    }

    /**
     * Handle the response received from the Discovery Endpoint and connect with the Authentication Endpoint.
     */
    private void revokeAuthorizationEndpoint(AuthenticationContext context, HttpServletRequest request,
                                              HttpServletResponse response) throws
            AuthenticationFailedException {

        //retrieve the properties configured
        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();

        //decode the json object returned from the Discovery API
        JSONObject jsonObject = (JSONObject) context.
                getProperty(MCAuthenticatorConstants.MC_DISCOVERY_JSON_OBJECT);

        String authorizationEndpoint = null;
        String tokenEndpoint = null;
        String userinfoEndpoint = null;
        String operatoridScope = null;
        String authorizationClientId = null;
        String authorizationSecret = null;
        String subscriberId = null;

        //this is maintained to check whether the authentication type is on-net or off-net
        String uiPromptStatus = (String) context.getProperty(MCAuthenticatorConstants
                .MC_ON_NET_STATUS);

        try {

            JSONObject jsonResponse = jsonObject.
                    getJSONObject(MCAuthenticatorConstants.MC_DISCOVERY_JSON_OBJECT);
            authorizationClientId = jsonResponse.
                    getString(MCAuthenticatorConstants.MC_AUTHORIZATION_CLIENT_ID);
            authorizationSecret = jsonResponse.
                    getString(MCAuthenticatorConstants.MC_AUTHORIZATION_CLIENT_SECRET);

            //retrieve subscriber id if off-net
            if (!("true").equals(uiPromptStatus)) {
                subscriberId = jsonObject.
                        getString(MCAuthenticatorConstants.MC_AUTHORIZATION_SUBSCRIBER_ID);
            } else {
                subscriberId = request.getParameter
                        (MCAuthenticatorConstants.MC_AUTHORIZATION_SUBSCRIBER_ID);
            }


            JSONObject apis = jsonResponse.
                    getJSONObject(MCAuthenticatorConstants.MC_AUTHORIZATION_APIS);
            JSONObject operatorid = apis.
                    getJSONObject(MCAuthenticatorConstants.MC_AUTHORIZATION_OPERATOR_ID);
            JSONArray operatoridLink = operatorid.
                    getJSONArray(MCAuthenticatorConstants.MC_AUTHORIZATION_LINK);

            for (int i = 0; i < operatoridLink.length(); i++) {
                String linkRef = operatoridLink.getJSONObject(i).getString(MCAuthenticatorConstants.
                        MC_LINK_REFERENCE);
                if (MCAuthenticatorConstants.MC_LINKS_AUTHORIZATION.equals(linkRef)) {
                    authorizationEndpoint = operatoridLink.getJSONObject(i).getString("href");
                } else if (MCAuthenticatorConstants.MC_LINKS_TOKEN.equals(linkRef)) {
                    tokenEndpoint = operatoridLink.getJSONObject(i).getString("href");
                } else if (MCAuthenticatorConstants.MC_LINKS_USERINFO.equals(linkRef)) {
                    userinfoEndpoint = operatoridLink.getJSONObject(i).getString("href");
                } else if (MCAuthenticatorConstants.MC_AUTHORIZATION_SCOPE.equals(linkRef)) {
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
                get(MCAuthenticatorConstants.MC_AUTHORIZATION_ACR_VALUES);
        //retrieve current state
        String state = context.getContextIdentifier() + "," +
                MCAuthenticatorConstants.MC_LOGIN_TYPE;

        //create oAuthClientrequest to contact the Authorization Endpooint
        try {
            OAuthClientRequest oAuthClientRequest;

            oAuthClientRequest = OAuthClientRequest
                    .authorizationLocation(authorizationEndpoint)
                    .setClientId(authorizationClientId)
                    .setRedirectURI(getCallbackUrl(authenticatorProperties))
                    .setResponseType(MCAuthenticatorConstants.MC_AUTHORIZATION_RESPONSE_TYPE)
                    .setScope(scope)
                    .setState(state)
                    .setParameter(MCAuthenticatorConstants.MC_AUTHORIZATION_ACR_VALUES,
                            acrValues)
                    .setParameter(MCAuthenticatorConstants.MC_AUTHORIZATION_NONCE, state)
                    .setParameter(MCAuthenticatorConstants.MC_AUTHORIZATION_LOGIN_HINT,
                            MCAuthenticatorConstants.MC_ENCR_MSISDN + ":" + subscriberId)
                    .buildQueryMessage();


            //set the context values to be used in the rest of the flow
            context.setProperty(MCAuthenticatorConstants.MC_FLOW_STATUS,
                    MCAuthenticatorConstants.MC_TOKEN_ENDPOINT);
            context.setProperty(MCAuthenticatorConstants.MC_TOKEN_ENDPOINT, tokenEndpoint);
            context.setProperty(MCAuthenticatorConstants.MC_USERINFO_ENDPOINT, userinfoEndpoint);
            context.setProperty(MCAuthenticatorConstants.MC_AUTHORIZATION_CLIENT_ID,
                    authorizationClientId);
            context.setProperty(MCAuthenticatorConstants.MC_AUTHORIZATION_CLIENT_SECRET,
                    authorizationSecret);
            context.setProperty(MCAuthenticatorConstants.OIDC_STATE,
                    state);

            //contact the authorization endpoint
            String url = oAuthClientRequest.getLocationUri();
            response.sendRedirect(url);

        } catch (OAuthSystemException | IOException e) {
            throw new AuthenticationFailedException("response redirection failed", e);
        }
    }


    /**
     * Read the discovery API endpoint connections.
     */
    private void discoveryEndpointRead(AuthenticationContext context,
                                       HttpServletResponse response, HttpURLConnection connection)
            throws AuthenticationFailedException {


        try {

            //get response from HttpURLConnection
            int responseCode = connection.getResponseCode();
            //if 200 OK
            if (responseCode == HttpStatus.SC_OK) {

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
                //create JSON object using the String retrieved
                JSONObject jsonObject = null;
                try {
                    jsonObject = new JSONObject(responseString);
                } catch (JSONException e) {
                    throw new AuthenticationFailedException("Exception occured while reading the" +
                            " discovery API endpoints", e);
                }
                //add the JSON object to the context of the session
                context.setProperty(MCAuthenticatorConstants.
                                MC_DISCOVERY_JSON_OBJECT,
                        jsonObject);
                //let the context know the end of the Discovery Process, and ste it to Authorization

                context.setProperty(MCAuthenticatorConstants.MC_FLOW_STATUS,
                        MCAuthenticatorConstants.MC_AUTHORIZATION_ENDPOINT);
                log.info("MSISDN is valid. Discovery Endpoint authorization successful");


            } else if (responseCode == HttpStatus.SC_MOVED_TEMPORARILY) {
                //if 302, move temporarily
                String redirectUrl = connection.getHeaderField(HttpHeaders.LOCATION);
                //retrieve the redirect URL and redirect the flow
                response.sendRedirect(redirectUrl);
                context.setProperty(MCAuthenticatorConstants.MC_FLOW_STATUS,
                        MCAuthenticatorConstants.MC_AUTHORIZATION_ENDPOINT);
                log.error("MSISDN is invalid. Redirecting to mobile connect interface");

            } else if (responseCode == HttpStatus.SC_UNAUTHORIZED) {
                //if 401 unauthorized
                String retryURL = ConfigurationFacade.getInstance().getAuthenticationEndpointRetryURL();
                //redirect to retry URL
                response.sendRedirect(retryURL);
                log.error("No Authorization or Bad Session");

            } else if (responseCode == HttpStatus.SC_NOT_FOUND || responseCode == HttpStatus.SC_BAD_REQUEST) {
                //if 404, not found
                String retryURL = ConfigurationFacade.getInstance().getAuthenticationEndpointRetryURL();
                //redirect to retry URL
                response.sendRedirect(retryURL);
                log.error("Bad MSISDN is supplied");
            }

        } catch (IOException e) {
            throw new AuthenticationFailedException("response redirection failed", e);
        }

    }

    /**
     * Return the mobile connect scope from UI or Discovery API response.
     */
    private String getMobileConnectScope(Map<String, String> authenticatorProperties, String operatoridScope) throws
            AuthenticationFailedException {

        //retrieve mobile connect scope from the UI
        if (StringUtils.isNotEmpty(authenticatorProperties.
                get(MCAuthenticatorConstants.MC_AUTHORIZATION_SCOPE))) {
            return authenticatorProperties.get(MCAuthenticatorConstants.MC_AUTHORIZATION_SCOPE);
        } else if (StringUtils.isNotEmpty(operatoridScope)) {
            //retrieve the mobile connect scope from the discovery response
            return operatoridScope;
        } else {
            //if both the UI scope and Discovery response scope values are null
            throw new AuthenticationFailedException("MobileConnect Scope is not configured correctly");
        }

    }

    /**
     * Process the response of the Discovery and Mobile Connect API and contact the Token Endpoint.
     */
    private void tokenAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                            AuthenticationContext context)
            throws AuthenticationFailedException {

        //get authentication properties from the context
        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();

        //get the following values from the context of the flow
        String tokenEndpoint = (String) context.
                getProperty(MCAuthenticatorConstants.MC_TOKEN_ENDPOINT);
        String authorizationClientId = (String) context.
                getProperty(MCAuthenticatorConstants.MC_AUTHORIZATION_CLIENT_ID);
        String authorizationSecret = (String) context.
                getProperty(MCAuthenticatorConstants.MC_AUTHORIZATION_CLIENT_SECRET);

        try {

            String redirectURL = getCallbackUrl(authenticatorProperties);
            //get code sent back by the Token Endpoint
            String code = request.getParameter(MCAuthenticatorConstants.MC_TOKEN_CODE);


            //Base 64 encode the key and secret to attach as the header for URL connections
            String userPass = authorizationClientId + ":" + authorizationSecret;
            String authorizationHeader = "Basic " + Base64Utils.encode(userPass.getBytes(StandardCharsets.UTF_8));

            //encode query parameters
            redirectURL = URLEncoder.encode(redirectURL, String.valueOf(StandardCharsets.UTF_8));

            //prepare query parameters
            String queryParameters = "grant_type=" +
            MCAuthenticatorConstants.MC_TOKEN_GRANT_TYPE + "&redirect_uri=" +
                    redirectURL;

            //url with query parameters for TokenEndpoint API call
            String url = tokenEndpoint + "?" + "code=" + code + "&" + queryParameters;

            URL obj = new URL(url);
            HttpURLConnection connection = (HttpURLConnection) obj.openConnection();

            connection.setRequestMethod("POST");
            connection.setRequestProperty(MCAuthenticatorConstants.MC_DISCOVERY_AUTHORIZATION,
                    authorizationHeader);
            connection.setRequestProperty(HttpHeaders.CONTENT_TYPE,
                    MediaType.APPLICATION_FORM_URLENCODED);

            //if the connection is unauthorized
            if (connection.getResponseCode() == 401 || connection.getResponseCode() == 400) {
                    throw new AuthenticationFailedException("Invalid Token. Authentication failed");
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
                context.setProperty(MCAuthenticatorConstants.MC_TOKEN_JSON_OBJECT,
                        jsonObject);

                log.info("Token Endpoint API call successful");

                //call the user info Authentication Endpoint to retrieve user information
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

            //retrieve the user info endpoint url from the Context
            String url = getUserInfoEndpointURL(context);

            JSONObject jsonObject = (JSONObject) context.
                    getProperty(MCAuthenticatorConstants.MC_TOKEN_JSON_OBJECT);

            //decode JSON Object
            String accessToken = jsonObject.getString(MCAuthenticatorConstants.ACCESS_TOKEN);
            String tokenType = jsonObject.getString(MCAuthenticatorConstants.TOKEN_TYPE);
            String idToken = jsonObject.getString(MCAuthenticatorConstants.ID_TOKEN);

            //encode query parameters
            accessToken = URLEncoder.encode(accessToken, String.valueOf(StandardCharsets.UTF_8));
            tokenType = URLEncoder.encode(tokenType, String.valueOf(StandardCharsets.UTF_8));
            idToken = URLEncoder.encode(idToken, String.valueOf(StandardCharsets.UTF_8));

            //prepare query parameters
            String queryParameters = "access_token=" + accessToken + "&token_type=" + tokenType + "&id_token=" +
                    idToken;

            //add query parameters
            url = url + "?" + queryParameters;

            HttpGet httpGet = new HttpGet(url);
            String tokenValue = "Bearer " + accessToken;

            //add header values required
            httpGet.addHeader(MCAuthenticatorConstants.MC_DISCOVERY_AUTHORIZATION, tokenValue);

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

            context.setProperty(MCAuthenticatorConstants.MC_USER_INFO_JSON_OBJECT
                    , jsonUserInfo);


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
    private String getUserInfoEndpointURL(AuthenticationContext context) throws AuthenticationFailedException {

        String url = (String) context.
                getProperty(MCAuthenticatorConstants.MC_USERINFO_ENDPOINT);
        if (StringUtils.isNotEmpty(url)) {
            return url;
        } else {
            throw new AuthenticationFailedException("User Info Endpoint not found");
        }
    }


    /**
     * Execute the URL Get request.
     */
    private HttpResponse connectURL_get(HttpGet request)
            throws IOException {

        //create client while disabling Redirect handling
        CloseableHttpClient client = HttpClientBuilder.create().disableRedirectHandling().build();

        return client.execute(request);

    }

    /**
     * Call the Operator Selection UI of the Discovery Endpoint.
     */
    private HttpResponse operatorSelectionDiscoveryCall(String authorizationHeader, AuthenticationContext context)
            throws IOException {

        //prepare query parameters

        String queryParameters = MCAuthenticatorConstants.MC_DISCOVERY_REDIRECT_URL + "=" +
                getCallbackUrl(context.getAuthenticatorProperties());


        String discoveryAPIURL =  getAuthenticatorConfig().getParameterMap().get(MCAuthenticatorConstants
                .DISCOVERY_API_URL);

        if (StringUtils.isEmpty(discoveryAPIURL)) {
            //assigning the default URL for the discoveryAPIURL hence the URL is not added in configuration file
            discoveryAPIURL = "https://discover.mobileconnect.io/gsma/v2/discovery/";
            log.warn("Discovery API URL is not configured, hence using the default value : " + discoveryAPIURL);
        }

        //url to call the Discovery API endpoint for operator selection URL
        String url = discoveryAPIURL + "?" + queryParameters;

        if (log.isDebugEnabled()) {
            log.debug("Eoperation Selection Discovery Call process with the URL : " + url);
        }

        HttpGet httpGet = new HttpGet(url);

        //add header values required
        httpGet.addHeader(MCAuthenticatorConstants.MC_DISCOVERY_AUTHORIZATION,
                authorizationHeader);
        httpGet.addHeader(HttpHeaders.ACCEPT,
                MediaType.APPLICATION_XML);

        //connect to the user info endpoint
        return connectURL_get(httpGet);
    }

    /**
     * msisdn based Discovery (Developer app uses Discovery API to send msisdn).
     */
    private HttpURLConnection msisdnBasedDiscoveryProcess(String authorizationHeader, String msisdn, String callbackURL)
            throws IOException {

        //prepare query parameters
        String queryParameters = MCAuthenticatorConstants.MC_DISCOVERY_REDIRECT_URL + "=" +
                callbackURL;

        String discoveryAPIURL =  getAuthenticatorConfig().getParameterMap().get(MCAuthenticatorConstants
                .DISCOVERY_API_URL);

        if (StringUtils.isEmpty(discoveryAPIURL)) {
            //assigning the default URL for the discoveryAPIURL hence the URL is not added in configuration file
            discoveryAPIURL = "https://discover.mobileconnect.io/gsma/v2/discovery/";
            log.warn("Discovery API URL is not configured, hence using the default value : " + discoveryAPIURL);
        }

        //create url to make the API call
        String url = discoveryAPIURL + "?" + queryParameters;


        //body parameters for the API call
        String data = "MSISDN=" + msisdn;

        URL obj = new URL(url);
        HttpURLConnection connection = (HttpURLConnection) obj.openConnection();

        if (log.isDebugEnabled()) {
            log.debug("Trying to discover the mobile service providers endpoint with the mobile number provided");
        }

        connection.setRequestMethod(HttpMethod.POST);
        connection.setRequestProperty(MCAuthenticatorConstants.MC_DISCOVERY_AUTHORIZATION,
                authorizationHeader);
        connection.setRequestProperty(HttpHeaders.ACCEPT,
                MediaType.APPLICATION_XML);
        connection.setDoOutput(true);

        //write data to the body of the connection
        DataOutputStream outputStream = new DataOutputStream(connection.getOutputStream());
        outputStream.writeBytes(data);
        outputStream.close();

        return connection;
    }


    /**
     * Build the claims required to follow up the process.
     */
    private void buildClaims(AuthenticationContext context, String jsonString)
            throws ApplicationAuthenticatorException {

        final String claimDialectUri = getClaimDialectURI();
        final boolean shouldPrefixClaimDialectUri = shouldPrefixClaimDialectUri();
        final ClaimConfig claimConfig = context.getExternalIdP().getIdentityProvider().getClaimConfig();
        final String userClaimUri = claimConfig.getUserClaimURI();
        final boolean isLocalClaimDialect = claimConfig.isLocalClaimDialect();
        final boolean isUserClaimUriBlank = StringUtils.isBlank(userClaimUri);
        Map<String, Object> userClaims = JSONUtils.parseJSON(jsonString);

        if (userClaims != null) {
            Map<ClaimMapping, String> claims = new HashMap<>();
            String claimUri = null;
            String claimValue = null;
            for (Map.Entry<String, Object> entry : userClaims.entrySet()) {
                claimUri = getEffectiveClaimUri(claimDialectUri, entry.getKey(),
                        shouldPrefixClaimDialectUri);
                if (entry.getValue() != null) {
                    claimValue = entry.getValue().toString();
                }
                if (StringUtils.isNotEmpty(claimUri) && StringUtils.isNotEmpty(claimValue)) {
                    claims.put(ClaimMapping.build(claimUri, claimUri, null, false), claimValue);
                }

                if (log.isDebugEnabled() &&
                        IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.USER_CLAIMS)) {
                    log.debug("Adding claim mapping : " + claimUri + " <> " + claimUri + " : "
                            + claimValue);
                }
            }

            if (isUserClaimUriBlank) {
                //Set id as the default userClaimUri in IDP claim Configs.
                context.getExternalIdP().getIdentityProvider().getClaimConfig().setUserClaimURI
                        (getEffectiveClaimUri(claimDialectUri,
                                MCAuthenticatorConstants.DEFAULT_USER_IDENTIFIER, shouldPrefixClaimDialectUri));
            }

            if (isLocalClaimDialect && !isUserClaimUriBlank && StringUtils.isNotBlank(claimDialectUri)) {
                setSubject(context, userClaims);
                context.getSubject().setUserAttributes(claims);
                try {
                    String subjectFromClaims = FrameworkUtils.getFederatedSubjectFromClaims(context, claimDialectUri);
                    if (StringUtils.isNotBlank(subjectFromClaims)) {
                        context.getSubject().setAuthenticatedSubjectIdentifier(subjectFromClaims);
                    }
                } catch (FrameworkException ex) {
                    log.error("Error while retrieving subject from claims. " +
                            "Both Dedicated claim dialect (" + claimDialectUri +
                            ") and user ID Claim URI (" + userClaimUri + ") is Configured.", ex);
                }
            } else {
                String subjectFromClaims = FrameworkUtils.getFederatedSubjectFromClaims(
                        context.getExternalIdP().getIdentityProvider(), claims);
                if (StringUtils.isNotBlank(subjectFromClaims)) {
                    AuthenticatedUser authenticatedUser =
                            AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(subjectFromClaims);
                    context.setSubject(authenticatedUser);
                } else {
                    setSubject(context, userClaims);
                }
                context.getSubject().setUserAttributes(claims);
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Decoded json object is null");
            }
            throw new ApplicationAuthenticatorException("Decoded json object is null");
        }
    }

    /**
     * Prefix give ClaimDialactUri to given claimUri.
     */
    private String getEffectiveClaimUri(String claimDialectUri, String claimUri,
                                        boolean shouldPrefixClaimDialectUri) {

        if (shouldPrefixClaimDialectUri && StringUtils.isNotBlank(claimDialectUri)) {
            return claimDialectUri + "/" + claimUri;
        }
        return claimUri;
    }

    /**
     * Set the subject of the Authenticator in the context.
     */
    private void setSubject(AuthenticationContext context, Map<String, Object> jsonObject)
            throws ApplicationAuthenticatorException {

        String authenticatedUserId = String.valueOf(jsonObject.
                get(MCAuthenticatorConstants.DEFAULT_USER_IDENTIFIER));

        if (log.isDebugEnabled()) {
            log.debug("The subject claim that you have selected is null. The default subject claim : " +
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
        return MCAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    /**
     * Get the Name of the Authenticator.
     */
    @Override
    public String getName() {
        return MCAuthenticatorConstants.AUTHENTICATOR_NAME;
    }

    /**
     * Get the CallBackURL.
     */
    @Override
    protected String getCallbackUrl(Map<String, String> authenticatorProperties) {

        String callbackURL = authenticatorProperties.get(MCAuthenticatorConstants.MC_CALLBACK_URL);

        if (StringUtils.isNotEmpty(callbackURL)) {
            return authenticatorProperties.get(MCAuthenticatorConstants.MC_CALLBACK_URL);
        } else {
            //assigning the default URL for the callbackURL hence the URL is not added in UI
            callbackURL = "https://localhost:9443/commonauth";
            log.warn("callback URL is not found in the configurations, hence using the default value : " + callbackURL);
        }
        return callbackURL;
    }

    protected boolean shouldPrefixClaimDialectUri() {

        AuthenticatorConfig authConfig = FileBasedConfigurationBuilder.getInstance().getAuthenticatorBean(getName());
        if (authConfig != null) {
            Map<String, String> parameters = authConfig.getParameterMap();
            if (parameters != null) {
                return Boolean.parseBoolean(parameters.get(
                        MCAuthenticatorConstants.PREFIX_CLAIM_DIALECT_URI_PARAMETER));
            }
        }
        return false;
    }

    @Override
    public String getClaimDialectURI() {

        String claimDialectUri = super.getClaimDialectURI();
        AuthenticatorConfig authConfig = FileBasedConfigurationBuilder.getInstance().getAuthenticatorBean(getName());
        if (authConfig != null) {
            Map<String, String> parameters = authConfig.getParameterMap();
            if (parameters != null) {
                String customClaimDialectUri = parameters.get(
                        MCAuthenticatorConstants.CLAIM_DIALECT_URI_PARAMETER);
                if (StringUtils.isNotBlank(customClaimDialectUri)) {
                    claimDialectUri = customClaimDialectUri;
                }
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("Authenticator: " + getName() + " is using the claim dialect uri: " +
                    claimDialectUri);
        }
        return claimDialectUri;
    }

    /**
     * Get Configuration Properties.
     */
    @Override
    public List<Property> getConfigurationProperties() {

        List<Property> configProperties = new ArrayList<>();

        //set the mobile connect Authentication type
        Property authenticationType = new Property();
        authenticationType.setName(MCAuthenticatorConstants.MC_AUTHENTICATION_TYPE);
        authenticationType.setDisplayName("Mobile Connect Authentication Type");
        authenticationType.setRequired(false);
        authenticationType.setValue("on-net");
        authenticationType.setDescription("Type 'on-net' or 'off-net' to use relevant authentication type, in off-net" +
                "you will be providing the mobile number in WSO2 Identity Server webapp and in on net it will be in " +
                "GSMA webapp");
        authenticationType.setDisplayOrder(0);
        configProperties.add(authenticationType);

        //set the mobile connect key input field
        Property mobileConnectKey = new Property();
        mobileConnectKey.setName(MCAuthenticatorConstants.MC_API_KEY);
        mobileConnectKey.setDisplayName("Mobile Connect Key");
        mobileConnectKey.setRequired(false);
        mobileConnectKey.setConfidential(true);
        mobileConnectKey.setDescription("Enter the Mobile Connect Key of the Mobile Connect Application Account");
        mobileConnectKey.setDisplayOrder(1);
        configProperties.add(mobileConnectKey);

        //set the mobile connect secret input field
        Property mobileConnectSecret = new Property();
        mobileConnectSecret.setName(MCAuthenticatorConstants.MC_API_SECRET);
        mobileConnectSecret.setDisplayName("Mobile Connect Secret");
        mobileConnectSecret.setRequired(false);
        mobileConnectSecret.setConfidential(true);
        mobileConnectSecret.setDescription("Enter the Mobile Connect Secret of the Mobile Connect Application Account");
        mobileConnectSecret.setDisplayOrder(2);
        configProperties.add(mobileConnectSecret);

        //set the mobile connect scope input field
        Property mobileConnectScope = new Property();
        mobileConnectScope.setName(MCAuthenticatorConstants.MC_AUTHORIZATION_SCOPE);
        mobileConnectScope.setDisplayName("Mobile Connect Scope");
        mobileConnectScope.setRequired(true);
        mobileConnectScope.setValue("openid");
        mobileConnectScope.setDescription("Enter the Mobile Connect Scope Required");
        mobileConnectScope.setDisplayOrder(3);
        configProperties.add(mobileConnectScope);

        //set the mobile connect arc values
        Property mobileConnectAcrValues = new Property();
        mobileConnectAcrValues.setName(MCAuthenticatorConstants.MC_AUTHORIZATION_ACR_VALUES);
        mobileConnectAcrValues.setDisplayName("Mobile Connect ACR Values");
        mobileConnectAcrValues.setRequired(true);
        mobileConnectAcrValues.setValue("2");
        mobileConnectAcrValues.setDescription("Enter the Mobile Connect ACR Values required");
        mobileConnectAcrValues.setDisplayOrder(4);
        configProperties.add(mobileConnectAcrValues);


        //set the mobile connect claim for mobile number values
        Property mobileConnectMobileClaim = new Property();
        mobileConnectMobileClaim.setName(MCAuthenticatorConstants.MC_MOBILE_CLAIM);
        mobileConnectMobileClaim.setDisplayName("Mobile Connect Mobile Claim");
        mobileConnectMobileClaim.setRequired(true);
        mobileConnectMobileClaim.setValue(MCAuthenticatorConstants.MC_MOBILE_CLAIM_VALUE);
        mobileConnectMobileClaim.setDescription("Add the user claim which you are using for the mobile number");
        mobileConnectMobileClaim.setDisplayOrder(5);
        configProperties.add(mobileConnectMobileClaim);


        //set the mobile connect claim for mobile number values
        Property mobileConnectCallbackURL = new Property();
        mobileConnectCallbackURL.setName(MCAuthenticatorConstants.MC_CALLBACK_URL);
        mobileConnectCallbackURL.setDisplayName("Mobile Connect Callback URL");
        mobileConnectCallbackURL.setRequired(true);
        mobileConnectCallbackURL.setDescription("Enter value corresponding to callback url");
        mobileConnectCallbackURL.setDisplayOrder(6);
        configProperties.add(mobileConnectCallbackURL);


        return configProperties;
    }
}
