/*
 *  Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.authenticator.mobile.connect;

import org.apache.catalina.core.ApplicationContext;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.URLConnectionClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthClientResponse;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.apache.oltu.oauth2.common.utils.JSONUtils;
import org.codehaus.jettison.json.JSONArray;
import org.codehaus.jettison.json.JSONException;
import org.codehaus.jettison.json.JSONObject;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.ApplicationAuthenticatorException;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.util.*;

public class MobileConnectAuthenticator extends AbstractApplicationAuthenticator implements
        FederatedApplicationAuthenticator {

    private static final long serialVersionUID = -4844100162196896194L;
    private static final Log log = LogFactory.getLog(MobileConnectAuthenticator.class);
    private final String accept = "application/xml";
    private final String contentType = "application/x-www-form-urlencoded";
    private String authorizationEndpoint = "";
    private String tokenEndpoint = "";
    private String userinfoEndpoint = "";
    private String operatoridScope = "";
    private String authorizationCode = "";
    private String discovery_client_id = "";
    private String discovery_client_secret = "";
    private String basicAuth = "";
    private String accessToken = "";
    private String idToken = "";

    public static String executePost(String targetURL, String urlParameters, String accessTokenIdentifier) {
        URL url;
        HttpURLConnection connection = null;
        try {
            //Create connection
            url = new URL(targetURL);
            connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type",
                    "application/x-www-form-urlencoded");
            connection.setRequestProperty("Authorization", "Bearer " + accessTokenIdentifier);

            connection.setRequestProperty("Content-Length", "" +
                    Integer.toString(urlParameters.getBytes().length));
            connection.setRequestProperty("Content-Language", "en-US");

            connection.setUseCaches(false);
            connection.setDoInput(true);
            connection.setDoOutput(true);

            //Send request
            DataOutputStream wr = new DataOutputStream(
                    connection.getOutputStream());
            wr.writeBytes(urlParameters);
            wr.flush();
            wr.close();

            //Get Response
            InputStream is = connection.getInputStream();
            BufferedReader rd = new BufferedReader(new InputStreamReader(is));
            String line;
            StringBuffer response = new StringBuffer();
            while ((line = rd.readLine()) != null) {
                response.append(line);
                response.append('\r');
            }
            rd.close();
            return response.toString();

        } catch (Exception e) {

            e.printStackTrace();
            return null;

        } finally {

            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    public static String executeGet(String targetURL, String urlParameters, String accessTokenIdentifier) {
        try {
            URL myURL = new URL(targetURL);
            URLConnection myURLConnection = myURL.openConnection();
            myURLConnection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            myURLConnection.setRequestProperty("Authorization", "Bearer " + accessTokenIdentifier);
            myURLConnection.setRequestProperty("Content-Language", "en-US");
            myURLConnection.setUseCaches(false);
            myURLConnection.setDoInput(true);
            myURLConnection.setDoOutput(true);

            BufferedReader br = new BufferedReader(
                    new InputStreamReader(myURLConnection.getInputStream()));
            String line;
            StringBuffer response = new StringBuffer();
            while ((line = br.readLine()) != null) {
                response.append(line);
                response.append('\r');
            }
            br.close();
            return response.toString();
        } catch (Exception e) {
            // new URL() failed
            // ...
        }
        return "";
    }

    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request,
                                           HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException, LogoutFailedException {

        if (!context.isLogoutRequest()) {
            if (!canHandle(request)
                    || (request.getAttribute(FrameworkConstants.REQ_ATTR_HANDLED) != null && ((Boolean) request
                    .getAttribute(FrameworkConstants.REQ_ATTR_HANDLED)))) {

                if (context.getProperty("flowStatus") == null) {
                    initiateAuthenticationRequest(request, response, context);
                } else if (context.getProperty("flowStatus").equals("authorizationEndpoint")) {
                    authorizeAuthenticationRequest(request, response, context);
                } else if (context.getProperty("flowStatus").equals("tokenEndpoint")) {
                    tokenAuthenticationRequest(request, response, context);

                    try {
                        processAuthenticationResponse(request, response, context);
                        if (this instanceof LocalApplicationAuthenticator) {
                            if (!context.getSequenceConfig().getApplicationConfig().isSaaSApp()) {
                                String userDomain = context.getSubject().getTenantDomain();
                                String tenantDomain = context.getTenantDomain();
                                if (!StringUtils.equals(userDomain, tenantDomain)) {
                                    context.setProperty("UserTenantDomainMismatch", true);
                                    throw new AuthenticationFailedException("Service Provider tenant domain must be " +
                                            "equal to user tenant domain for non-SaaS applications");
                                }
                            }
                        }
                        request.setAttribute(FrameworkConstants.REQ_ATTR_HANDLED, true);
                        return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
                    } catch (AuthenticationFailedException e) {
                        Map<Integer, StepConfig> stepMap = context.getSequenceConfig().getStepMap();
                        boolean stepHasMultiOption = false;

                        if (stepMap != null && !stepMap.isEmpty()) {
                            StepConfig stepConfig = stepMap.get(context.getCurrentStep());

                            if (stepConfig != null) {
                                stepHasMultiOption = stepConfig.isMultiOption();
                            }
                        }

                        if (retryAuthenticationEnabled() && !stepHasMultiOption) {
                            context.setRetrying(true);
                            context.setCurrentAuthenticator(getName());
                            initiateAuthenticationRequest(request, response, context);
                            return AuthenticatorFlowStatus.INCOMPLETE;
                        } else {
                            throw e;
                        }
                    }
                }


                context.setCurrentAuthenticator(getName());
                return AuthenticatorFlowStatus.INCOMPLETE;
            }
            else {
                try {
                    processAuthenticationResponse(request, response, context);
                    if (this instanceof LocalApplicationAuthenticator) {
                        if (!context.getSequenceConfig().getApplicationConfig().isSaaSApp()) {
                            String userDomain = context.getSubject().getTenantDomain();
                            String tenantDomain = context.getTenantDomain();
                            if (!StringUtils.equals(userDomain, tenantDomain)) {
                                context.setProperty("UserTenantDomainMismatch", true);
                                throw new AuthenticationFailedException("Service Provider tenant domain must be " +
                                        "equal to user tenant domain for non-SaaS applications");
                            }
                        }
                    }
                    request.setAttribute(FrameworkConstants.REQ_ATTR_HANDLED, true);
                    return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
                } catch (AuthenticationFailedException e) {
                    Map<Integer, StepConfig> stepMap = context.getSequenceConfig().getStepMap();
                    boolean stepHasMultiOption = false;

                    if (stepMap != null && !stepMap.isEmpty()) {
                        StepConfig stepConfig = stepMap.get(context.getCurrentStep());

                        if (stepConfig != null) {
                            stepHasMultiOption = stepConfig.isMultiOption();
                        }
                    }

                    if (retryAuthenticationEnabled() && !stepHasMultiOption) {
                        context.setRetrying(true);
                        context.setCurrentAuthenticator(getName());
                        initiateAuthenticationRequest(request, response, context);
                        return AuthenticatorFlowStatus.INCOMPLETE;
                    } else {
                        throw e;
                    }
                }
            }
            // if a logout flow
        } else {
            try {
                if (!canHandle(request)) {
                    context.setCurrentAuthenticator(getName());
                    initiateLogoutRequest(request, response, context);
                    return AuthenticatorFlowStatus.INCOMPLETE;
                } else {
                    processLogoutResponse(request, response, context);
                    return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
                }
            } catch (UnsupportedOperationException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Ignoring UnsupportedOperationException.", e);
                }
                return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
            }
        }
    }

    @Override
    public String getContextIdentifier(HttpServletRequest request) {

        if (request.getSession().getAttribute(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_CONTEXT_IDENTIFIER) == null) {
            request.getSession().setAttribute(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_CONTEXT_IDENTIFIER,
                    request.getParameter(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_SESSION_DATA_KEY));
            return (String) request.getSession().getAttribute(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_SESSION_DATA_KEY);
        } else {
            return (String) request.getSession().getAttribute(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_CONTEXT_IDENTIFIER);
        }
    }

    /**
     * Check whether the authentication or logout request can be handled by the authenticator
     */
    public boolean canHandle(HttpServletRequest request) {


        Enumeration e = request.getParameterNames();
        int count = 0;
        while (e.hasMoreElements()) {
            count++;
            String temp = (String) e.nextElement();
            String state = (String) request.getSession().getAttribute("tokenStatus");
            if (temp.equals("code") && state == null) {
                request.getSession().setAttribute("tokenStatus", "okay");
                return true;
            }
            log.info(temp);
            log.info(request.getParameter(temp));

        }
//        Enumeration e1 = request.getHeaderNames();
//        while (e1.hasMoreElements()) {
//            String temp = (String) e1.nextElement();
//            log.info(temp);
//            log.info(request.getHeader(temp));
//
//        }

        String state = (String) request.getSession().getAttribute("canHandleStatus");
        if (state != null) {
            if (state.equals("incomplete")) {
                request.getSession().setAttribute("canHandleStatus", null);
                return true;
            }
            if (count == 0) {
                return true;
            }
            return false;

        }
        return false;


        //        return (request.getParameter(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_COMMONAUTH_IDP) != null
//                && request.getParameter(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_COMMONAUTH_AUTHENTICATOR) != null
//                && request.getParameter(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_COMMONAUTH_SDK) != null);
    }

    /**
     * Initiate the authentication request
     */
    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request,
                                                 HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();

        if (authenticatorProperties != null) {

            String mobileConnectKey = authenticatorProperties.get(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_API_KEY);
            String mobileConnectSecret = authenticatorProperties.get(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_API_SECRET);

            try {

                String userpass = mobileConnectKey + ":" + mobileConnectSecret;
                basicAuth = "Basic " + javax.xml.bind.DatatypeConverter.printBase64Binary(userpass.getBytes("UTF-8"));

                String queryParams = FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(),
                        context.getCallerSessionKey(), context.getContextIdentifier());

                String subStr = queryParams.substring(queryParams
                        .indexOf(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_SESSION_DATA_KEY + "="));

                String sessionDK = subStr.substring(subStr.indexOf(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_SESSION_DATA_KEY
                        + "="), subStr.indexOf("&")).replace((MobileConnectAuthenticatorConstants.MOBILE_CONNECT_SESSION_DATA_KEY + "=")
                        , "");

                //select the method of call needed
                HttpResponse urlResponse = discoveryMSISDN_ignoreCookies("+917795099975", authenticatorProperties, true, response);

                BufferedReader rd = new BufferedReader(new InputStreamReader(urlResponse.getEntity().getContent()));
                int statusCode = urlResponse.getStatusLine().getStatusCode();
                String jsonData = "";

                if (statusCode == 200 || statusCode == 301) {

                    String line = "";
                    while ((line = rd.readLine()) != null) {
                        log.info(line);
                        jsonData += line + "\n";
                    }
                    log.info("Authorization Successful");
                    response.addHeader("canHandleStatus", "incomplete");
                    request.getSession().setAttribute("canHandleStatus", "incomplete");
                    response.sendRedirect(MobileConnectAuthenticatorConstants.DISCOVERY_API_URL);

                } else if (statusCode == 401) {
                    String line = "";
                    while ((line = rd.readLine()) != null) {
                        log.info(line);
                        jsonData += line + "\n";

                    }
                    String url = ConfigurationFacade.getInstance().getAuthenticationEndpointRetryURL();
                    response.sendRedirect(url);
                    log.error("No Authorization or Bad Session");

                } else if (statusCode == 404) {
                    String line = "";
                    while ((line = rd.readLine()) != null) {
                        log.info(line);
                        jsonData += line + "\n";
                    }
                    log.error("Bad MSISDN is supplied");
                    throw new AuthenticationFailedException("Invalid MSISDN, Please provide a valid MSISDN");

                } else if (statusCode == 400) {
                    String line = "";
                    while ((line = rd.readLine()) != null) {
                        log.info(line);
                        jsonData += line + "\n";
                    }
                    log.error("Redirect URI is missing");

                } else {
                    String line = "";
                    while ((line = rd.readLine()) != null) {
                        log.info(line);
                        jsonData += line + "\n";
                    }
                }

                JSONObject jsonObject = new JSONObject(jsonData);

                request.getSession().setAttribute(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_RESPONSE_STATE, statusCode);
                request.getSession().setAttribute(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_SESSION_DATA_KEY, sessionDK);
                request.getSession().setAttribute(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_JSON_OBJECT, jsonObject);
                request.getSession().setAttribute(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_SESSION_STATE, MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY);

                context.setProperty("flowStatus", "authorizationEndpoint");


            } catch (IOException e) {
                e.printStackTrace();
            } catch (org.codehaus.jettison.json.JSONException e) {
                e.printStackTrace();
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Error while retrieving properties. Authenticator Properties cannot be null");
            }
            throw new AuthenticationFailedException(" Authenticator Properties cannot be null");

        }

    }

    /**
     * Process the response of the Discovery and Mobile Connect API
     */
    protected void authorizeAuthenticationRequest(HttpServletRequest request,
                                                  HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        String client_id = "CijTuPz1hd3rormpV1IrCcbW5xQa";
        authorizationEndpoint = "https://localhost:9444/oauth2/authorize";
        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();


        String queryParams = FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(),
                context.getCallerSessionKey(), context.getContextIdentifier());

        String subStr = queryParams.substring(queryParams
                .indexOf(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_SESSION_DATA_KEY + "="));

        String sessionDK = subStr.substring(subStr.indexOf(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_SESSION_DATA_KEY
                + "="), subStr.indexOf("&")).replace((MobileConnectAuthenticatorConstants.MOBILE_CONNECT_SESSION_DATA_KEY + "=")
                , "");

        try {
            OAuthClientRequest authzRequest = OAuthClientRequest
                    .authorizationLocation(authorizationEndpoint)
                    .setClientId(client_id)
                    .setRedirectURI(getCallbackUrl(authenticatorProperties))
                    .setResponseType("code")
                    .setScope("openid")
                    .setState(sessionDK)
                    .buildQueryMessage();

            response.sendRedirect(authzRequest.getLocationUri());
            request.getSession().setAttribute("canHandleStatus", "incomplete");


//            request.getSession().setAttribute(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_SESSION_DATA_KEY, sessionDK);
//            request.getSession().setAttribute(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_CONTEXT_IDENTIFIER, sessionDK);
            context.setProperty("flowStatus", "tokenEndpoint");

            //response.sendRedirect(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_CALLBACK_URL);

        } catch (OAuthSystemException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }


    }

    /**
     * Process the response of the Discovery and Mobile Connect API
     */
    protected void tokenAuthenticationRequest(HttpServletRequest request,
                                              HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();


        try {

            String redirect_URL = getCallbackUrl(authenticatorProperties);

            tokenEndpoint = "https://localhost:9444/oauth2/token";
            HttpGet httpGet = new HttpGet(tokenEndpoint);
            String consumerSecret = "TTFFTDnbB5piYvQCMSApLmY9RDka";
            String consumerKey = "CijTuPz1hd3rormpV1IrCcbW5xQa";
            String code = request.getParameter("code");

            OAuthClientRequest accessRequest = OAuthClientRequest.tokenLocation(tokenEndpoint)
                    .setGrantType(GrantType.AUTHORIZATION_CODE)
                    .setClientId(consumerKey)
                    .setClientSecret(consumerSecret)
                    .setRedirectURI(redirect_URL)
                    .setCode(code)
                    .buildBodyMessage();

            OAuthClient oAuthClient = new OAuthClient(new URLConnectionClient());

            OAuthClientResponse oAuthResponse = oAuthClient.accessToken(accessRequest);
            accessToken = oAuthResponse.getParam("access_token");
            idToken = oAuthResponse.getParam("id_token");


//            String url = "https://localhost:9443/oauth2/userinfo?schema=openid";
//            OAuthClientRequest accessRequest2 = OAuthClientRequest.tokenLocation(url)
//                    .buildBodyMessage();
//
//            OAuthClient oAuthClient2 = new OAuthClient(new URLConnectionClient());
//            accessRequest2.setHeader("Authorization" , "Bearer "  + accessToken);
//
//            OAuthClientResponse oAuthResponse2 = oAuthClient2.accessToken(accessRequest2);


            userinfoAuthenticationresponse(accessToken, response, context);


            //response.sendRedirect(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_CALLBACK_URL);
        } catch (OAuthSystemException e) {
            e.printStackTrace();
        } catch (OAuthProblemException e) {
            e.printStackTrace();
        }


    }

    protected void userinfoAuthenticationresponse(String accessTokenIdentifier , HttpServletResponse response , AuthenticationContext context) {

        HttpResponse urlResponse = null;
        try {
            urlResponse = userinfoEndpoint_Access(accessTokenIdentifier);
            BufferedReader rd = new BufferedReader(new InputStreamReader(urlResponse.getEntity().getContent()));
            int statusCode = urlResponse.getStatusLine().getStatusCode();
            String jsonData = "";

            String line = "";
            while ((line = rd.readLine()) != null) {
                log.info(line);
                jsonData += line + "\n";
            }
            log.info("Authorization Successful");

            context.setProperty("jsonObject" , jsonData);


            //response.sendRedirect(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_CALLBACK_URL);
            //buildClaims(context, jsonData);


        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {


        String jsonObject = (String) context.getProperty("jsonObject");
        try {
            buildClaims(context, jsonObject);
        } catch (ApplicationAuthenticatorException e) {
            e.printStackTrace();
        }

//        String sessionKey = (String) request.getSession().getAttribute(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_SESSION_DATA_KEY);
//        String state = (String) request.getSession().getAttribute(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_SESSION_STATE);
//
//        if (state != null) {
//
//            int discoveryStatusCode = (int) request.getSession().getAttribute(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_RESPONSE_STATE);
//
//            if ((state).equals(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY) && (discoveryStatusCode == 200 || discoveryStatusCode == 301)) {
//                try {
//                    JSONObject jsonObject = (JSONObject) request.getSession().getAttribute(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_JSON_OBJECT);
//                    String ttl = jsonObject.getString("ttl");
//
//                    JSONObject jsonResponse = jsonObject.getJSONObject("response");
//                    discovery_client_id = jsonResponse.getString("client_id");
//                    discovery_client_secret = jsonResponse.getString("client_secret");
//                    String subscriber_id = jsonResponse.getString("subscriber_id");
//                    String serving_operator = jsonResponse.getString("serving_operator");
//                    String country = jsonResponse.getString("country");
//                    String currency = jsonResponse.getString("currency");
//
//                    JSONObject apis = jsonResponse.getJSONObject("apis");
//                    JSONObject operatorid = apis.getJSONObject("operatorid");
//
//                    JSONArray operatoridLink = operatorid.getJSONArray("link");
//
//                    for (int i = 0; i < operatoridLink.length(); i++) {
//                        String linkRef = operatoridLink.getJSONObject(i).getString("rel");
//                        if (linkRef.equals("authorization")) {
//                            authorizationEndpoint = operatoridLink.getJSONObject(i).getString("href");
//                        }
//                        if (linkRef.equals("token")) {
//                            tokenEndpoint = operatoridLink.getJSONObject(i).getString("href");
//                        }
//                        if (linkRef.equals("userinfo")) {
//                            userinfoEndpoint = operatoridLink.getJSONObject(i).getString("href");
//                        }
//                        if (linkRef.equals("scope")) {
//                            operatoridScope = operatoridLink.getJSONObject(i).getString("href");
//                        }
//                    }
//
//                    Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
//                    String redirect_URL = getCallbackUrl(authenticatorProperties);
//
//                    String client_id = "CijTuPz1hd3rormpV1IrCcbW5xQa";
//                    authorizationEndpoint = "https://localhost:9444/oauth2/authorize";
//
//                    OAuthClientRequest authzRequest = OAuthClientRequest
//                            .authorizationLocation(authorizationEndpoint)
//                            .setClientId(client_id)
//                            .setRedirectURI(getCallbackUrl(authenticatorProperties))
//                            .setResponseType("code")
//                            .setScope("openid")
//                            .buildQueryMessage();
//                    //response.sendRedirect(authzRequest.getLocationUri());
//                    response.sendRedirect(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_CALLBACK_URL);
//                    //context.setSubject();
//
//                    return;
////                    String url = authorizationEndpoint + "?scope=openid&response_type=code&redirect_uri=" +
////                            redirect_URL + "&client_id=" + client_id;
////                    response.sendRedirect(url);
////                    HttpGet httpGet = new HttpGet(authorizationEndpoint);
////                    HttpGet httpGet = new HttpGet(MobileConnectAuthenticatorConstants.DISCOVERY_API_URL);
////                    httpGet.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_AUTHORIZATION_CLIENT_ID, discovery_client_id);
////                    httpGet.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_AUTHORIZATION_RESPONSE_TYPE, "code");
////                    httpGet.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_AUTHORIZATION_SCOPE, "openid");
////                    httpGet.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_AUTHORIZATION_REDIRECT_URI, redirect_URL);
////                    httpGet.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_AUTHORIZATION_ARC_VALUES, "3 2");
////                    httpGet.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_AUTHORIZATION_STATE, sessionKey);
////                    httpGet.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_AUTHORIZATION_NONCE, sessionKey);
////                    HttpResponse urlResponse = connectURL_get(httpGet);
////                    response.sendRedirect(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_CALLBACK_URL);
////
////                    BufferedReader rd = new BufferedReader(new InputStreamReader(urlResponse.getEntity().getContent()));
////                    int statusCode = urlResponse.getStatusLine().getStatusCode();
////                    String jsonData = "";
////
////                    String line = "";
////                    while ((line = rd.readLine()) != null) {
////                        log.info(line);
////                        jsonData += line + "\n";
////                    }
////                    JSONObject jsonObjectAuthorization = new JSONObject(jsonData);
////
////                    authorizationCode = jsonObjectAuthorization.getString("code");
////                    String authorizationState = jsonObjectAuthorization.getString("state");
//
//
//                    //Check whether the Authorization State is the same as the one in the request
//                    //  if (authorizationState.equals(sessionKey)) {
//
////                    String queryParams = FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(),
////                            context.getCallerSessionKey(), context.getContextIdentifier());
////
////                    String subStr = queryParams.substring(queryParams
////                            .indexOf(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_SESSION_DATA_KEY + "="));
////
////                    String sessionDK = subStr.substring(subStr.indexOf(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_SESSION_DATA_KEY
////                            + "="), subStr.indexOf("&")).replace((MobileConnectAuthenticatorConstants.MOBILE_CONNECT_SESSION_DATA_KEY + "=")
////                            , "");
////
////                    request.getSession().setAttribute(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_SESSION_DATA_KEY, sessionDK);
////                    request.getSession().setAttribute(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_SESSION_STATE, MobileConnectAuthenticatorConstants.MOBILE_CONNECT_AUTHORIZATION_ENDPOINT);
//
//                    // }
////                    System.out.println(url);
//
//
//                } catch (org.codehaus.jettison.json.JSONException e) {
//                    e.printStackTrace();
//                } catch (IOException e) {
//                    e.printStackTrace();
//                } catch (OAuthSystemException e) {
//                    e.printStackTrace();
//                }
//
//            }
//            if ((state).equals(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_AUTHORIZATION_ENDPOINT)) {
//
//                ;
//                try {
//                    String userpass = discovery_client_id + ":" + discovery_client_secret;
//                    String basicAuth = "Basic " + javax.xml.bind.DatatypeConverter.printBase64Binary(userpass.getBytes("UTF-8"));
//
//
//                    Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
//                    String redirect_URL = getCallbackUrl(authenticatorProperties);
//
//                    tokenEndpoint = "https://localhost:9444/oauth2/token";
//                    HttpGet httpGet = new HttpGet(tokenEndpoint);
//                    String consumerSecret = "TTFFTDnbB5piYvQCMSApLmY9RDka";
//                    String consumerKey = "CijTuPz1hd3rormpV1IrCcbW5xQa";
//                    String code = request.getParameter("code");
//
//                    OAuthClientRequest accessRequest = OAuthClientRequest.tokenLocation(tokenEndpoint)
//                            .setGrantType(GrantType.AUTHORIZATION_CODE)
//                            .setClientId(consumerKey)
//                            .setClientSecret(consumerSecret)
//                            .setRedirectURI(request.getParameter("callbackurl"))
//                            .setCode(code)
//                            .buildBodyMessage();
//
//                    OAuthClient oAuthClient = new OAuthClient(new URLConnectionClient());
//
//                    OAuthClientResponse oAuthResponse = oAuthClient.accessToken(accessRequest);
//                    accessToken = oAuthResponse.getParam("oauth_token");
//                    idToken = oAuthResponse.getParam("id_token");
//
////
////                    httpGet.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_TOKEN_AUTHORIZATION, basicAuth);
////                    httpGet.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_TOKEN_CONTENT_TYPE, "application/x-www-form-urlencoded");
////                    httpGet.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_TOKEN_CODE, authorizationCode);
////                    httpGet.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_TOKEN_GRANT_TYPE, "authorization_code");
////                    httpGet.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_TOKEN_REDIRECT_URI, redirect_URL);
////                    HttpResponse urlResponse = connectURL_get(httpGet);
////
////                    BufferedReader rd = new BufferedReader(new InputStreamReader(urlResponse.getEntity().getContent()));
////                    int statusCode = urlResponse.getStatusLine().getStatusCode();
////                    String jsonData = "";
////
////                    String line = "";
////                    while ((line = rd.readLine()) != null) {
////                        log.info(line);
////                        jsonData += line + "\n";
////                    }
////                    JSONObject jsonObjectToken = new JSONObject(jsonData);
////
////                    String access_token = jsonObjectToken.getString("access_token");
////                    String token_type = jsonObjectToken.getString("token_type");
////                    String expires_in = jsonObjectToken.getString("expires_in");
////                    String id_token = jsonObjectToken.getString("id_token");
////                    String refresh_token = jsonObjectToken.getString("refresh_token");
////
////                    //decode id token
////                    org.apache.commons.codec.binary.Base64 decoder = new org.apache.commons.codec.binary.Base64(true);
////                    byte[] decodedBytes = decoder.decode(id_token);
////                    JSONObject jsonObjectIdToken = new JSONObject(new String(decodedBytes));
////
////                    String nonce = jsonObjectIdToken.getString("nonce");
////                    String sub = jsonObjectIdToken.getString("sub");
////                    String iat = jsonObjectIdToken.getString("iat");
////                    String exp = jsonObjectIdToken.getString("exp");
////                    String iss = jsonObjectIdToken.getString("iss");
////
////                    buildClaims(context, new String(decodedBytes));
//
//
//                } catch (IOException e) {
//                    e.printStackTrace();
//                } catch (OAuthSystemException e) {
//                    e.printStackTrace();
//                } catch (OAuthProblemException e) {
//                    e.printStackTrace();
//                }
////                catch (org.codehaus.jettison.json.JSONException e) {
////                    e.printStackTrace();
////                } catch (ApplicationAuthenticatorException e) {
////                    e.printStackTrace();
////                }
//
////
//            }
//            if ((state).equals(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_TOKEN_ENDPOINT)) {
//
////                userinfoEndpoint = "https://localhost:9443/oauth2/userinfo?schema=openid";
////                OAuth2TokenValidationRequestDTO  oauthReq = new OAuth2TokenValidationRequestDTO();
////                OAuth2TokenValidationRequestDTO_OAuth2AccessToken accessToken =  new OAuth2TokenValidationRequestDTO_OAuth2AccessToken();
////                OAuth2TokenValidationRequestDTO_TokenValidationContextParam[] contextParams =
////                        new OAuth2TokenValidationRequestDTO_TokenValidationContextParam[1];
////                OAuth2TokenValidationRequestDTO_TokenValidationContextParam resourceUriParam =
////                        new OAuth2TokenValidationRequestDTO_TokenValidationContextParam();
//
//            }
////            if ((state).equals(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_USERINFO_ENDPOINT)) {
////
////            }
//
//        }
//
////        Enumeration temp = request.getSession().getAttributeNames();
////        while (temp.hasMoreElements()) {
////            String temp2 = (String) temp.nextElement();
////            log.info("-----------------Keet------------" + temp2);
////            log.info("-----------------Keet------------" + request.getSession().getAttribute(temp2));
////        }


    }


    /**
     * Execute the URL Get request
     */
    protected HttpResponse connectURL_get(HttpGet request)
            throws IOException {

        CloseableHttpClient client = HttpClientBuilder.create().build();
        return client.execute(request);

    }

    /**
     * Execute the URL Post request
     */
    protected HttpResponse connectURL_post(HttpPost request)
            throws IOException {

        CloseableHttpClient client = HttpClientBuilder.create().build();
        return client.execute(request);

    }

    /**
     * MCC / MNC Discovery with GET verb
     */
    protected HttpResponse userinfoEndpoint_Access(String accessToken)
            throws IOException {

        String url = "https://localhost:9444/oauth2/userinfo?schema=openid";

        HttpGet httpGet = new HttpGet(url);

        String tokenValue = "Bearer " + accessToken;

        httpGet.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_AUTHORIZATION, tokenValue);

        HttpResponse urlResponse = connectURL_get(httpGet);

        return urlResponse;

    }


    /**
     * MCC / MNC Discovery with GET verb
     */
    protected HttpResponse discoveryMCCMNC_get(String MNC, String MCC, Map<String, String> authenticatorProperties, HttpServletResponse response)
            throws IOException {

        String url = MobileConnectAuthenticatorConstants.DISCOVERY_API_URL + "?"
                + MobileConnectAuthenticatorConstants.DISCOVERY_IDENTIFIED_MCC + "=" + MCC + "&"
                + MobileConnectAuthenticatorConstants.DISCOVERY_IDENTIFIED_MNC + "=" + MNC + "&"
                + MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_REDIRECT_URL + "=" +
                getCallbackUrl(authenticatorProperties);

        HttpGet httpGet = new HttpGet(url);

        httpGet.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_AUTHORIZATION, basicAuth);
        httpGet.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_ACCEPT, accept);

        HttpResponse urlResponse = connectURL_get(httpGet);

        response.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_AUTHORIZATION, basicAuth);
        response.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_ACCEPT, accept);
        response.sendRedirect(url);

        return urlResponse;

    }

    /**
     * MCC / MNC Discovery with POST verb
     */
    protected HttpResponse discoveryMCCMNC_post(String MNC, String MCC, Map<String, String> authenticatorProperties, HttpServletResponse response)
            throws IOException {

        String url = MobileConnectAuthenticatorConstants.DISCOVERY_API_URL;

        HttpPost httpPost = new HttpPost(url);

        httpPost.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_AUTHORIZATION, basicAuth);
        httpPost.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_ACCEPT, accept);
        httpPost.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_CONTENT_TYPE, contentType);
        httpPost.addHeader(MobileConnectAuthenticatorConstants.DISCOVERY_IDENTIFIED_MCC, MCC);
        httpPost.addHeader(MobileConnectAuthenticatorConstants.DISCOVERY_IDENTIFIED_MNC, MNC);
        httpPost.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_REDIRECT_URL, getCallbackUrl(authenticatorProperties));
        HttpResponse urlResponse = connectURL_post(httpPost);

        response.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_AUTHORIZATION, basicAuth);
        response.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_ACCEPT, accept);
        response.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_CONTENT_TYPE, contentType);
        response.addHeader(MobileConnectAuthenticatorConstants.DISCOVERY_IDENTIFIED_MCC, MCC);
        response.addHeader(MobileConnectAuthenticatorConstants.DISCOVERY_IDENTIFIED_MNC, MNC);
        response.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_REDIRECT_URL, getCallbackUrl(authenticatorProperties));
        response.sendRedirect(url);

        return urlResponse;

    }

    /**
     * Discovery request with Ignore Cookies flag - MCC/MNC Request
     */
    protected HttpResponse discoveryMCCMNC_ignoreCookies(String MNC, String MCC, Map<String, String> authenticatorProperties, boolean cookie, HttpServletResponse response)
            throws IOException {

        String url = MobileConnectAuthenticatorConstants.DISCOVERY_API_URL + "?"
                + MobileConnectAuthenticatorConstants.DISCOVERY_IDENTIFIED_MCC + "=" + MCC + "&"
                + MobileConnectAuthenticatorConstants.DISCOVERY_IDENTIFIED_MNC + "=" + MNC + "&"
                + MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_REDIRECT_URL + "=" +
                getCallbackUrl(authenticatorProperties) + "&"
                + MobileConnectAuthenticatorConstants.DISCOVERY_IGNORE_COOKIES + "=" + String.valueOf(cookie);

        HttpGet httpGet = new HttpGet(url);

        httpGet.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_AUTHORIZATION, basicAuth);
        httpGet.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_ACCEPT, accept);
        HttpResponse urlResponse = connectURL_get(httpGet);

        response.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_AUTHORIZATION, basicAuth);
        response.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_ACCEPT, accept);
        response.sendRedirect(url);

        return urlResponse;

    }

    /**
     * Discovery request with Ignore Cookes flag: MSISDN Based POST request
     */
    protected HttpResponse discoveryMSISDN_ignoreCookies(String MSISDN, Map<String, String> authenticatorProperties, boolean cookie, HttpServletResponse response)
            throws IOException {

        String url = MobileConnectAuthenticatorConstants.DISCOVERY_API_URL + "?" +
                MobileConnectAuthenticatorConstants.DISCOVERY_IGNORE_COOKIES + "=" + String.valueOf(cookie);

        HttpPost httpPost = new HttpPost(url);

        httpPost.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_AUTHORIZATION, basicAuth);
        httpPost.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_ACCEPT, accept);
        httpPost.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_CONTENT_TYPE, contentType);
        httpPost.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_MSISDN, MSISDN);
        httpPost.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_REDIRECT_URL, getCallbackUrl(authenticatorProperties));
        HttpResponse urlResponse = connectURL_post(httpPost);

        response.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_AUTHORIZATION, basicAuth);
        response.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_ACCEPT, accept);
        response.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_CONTENT_TYPE, contentType);
        response.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_MSISDN, MSISDN);
        response.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_REDIRECT_URL, getCallbackUrl(authenticatorProperties));
//        response.sendRedirect(url);

        return urlResponse;

    }

    /**
     * Discovery request with Set-Cookies=false
     */
    protected HttpResponse discoveryMCCMNC_setCookies(String MNC, String MCC, Map<String, String> authenticatorProperties, boolean cookie, HttpServletResponse response)
            throws IOException {

        String url = MobileConnectAuthenticatorConstants.DISCOVERY_API_URL + "?"
                + MobileConnectAuthenticatorConstants.DISCOVERY_IDENTIFIED_MCC + "=" + MCC + "&"
                + MobileConnectAuthenticatorConstants.DISCOVERY_IDENTIFIED_MNC + "=" + MNC + "&"
                + MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_REDIRECT_URL + "=" +
                getCallbackUrl(authenticatorProperties) + "&"
                + MobileConnectAuthenticatorConstants.DISCOVERY_SET_COOKIES + "=" + String.valueOf(cookie);

        HttpGet httpGet = new HttpGet(url);

        httpGet.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_AUTHORIZATION, basicAuth);
        httpGet.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_ACCEPT, accept);
        HttpResponse urlResponse = connectURL_get(httpGet);

        response.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_AUTHORIZATION, basicAuth);
        response.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_ACCEPT, accept);
        response.sendRedirect(url);

        return urlResponse;

    }

    /**
     * MSISDN based Discovery (Developer app uses Discovery API to send MSISDN)
     */
    protected HttpResponse discoveryMSISDN(String MSISDN, Map<String, String> authenticatorProperties, HttpServletResponse response)
            throws IOException {

        String url = MobileConnectAuthenticatorConstants.DISCOVERY_API_URL;

        HttpPost httpPost = new HttpPost(url);

        httpPost.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_AUTHORIZATION, basicAuth);
        httpPost.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_ACCEPT, accept);
        httpPost.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_CONTENT_TYPE, contentType);
        httpPost.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_MSISDN, MSISDN);
        httpPost.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_REDIRECT_URL, getCallbackUrl(authenticatorProperties));
        HttpResponse urlResponse = connectURL_post(httpPost);

        response.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_AUTHORIZATION, basicAuth);
        response.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_ACCEPT, accept);
        response.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_CONTENT_TYPE, contentType);
        response.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_MSISDN, MSISDN);
        response.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_REDIRECT_URL, getCallbackUrl(authenticatorProperties));
        response.sendRedirect(url);

        return urlResponse;

    }

    /**
     * MSISDN Based Discovery (Followed after user interaction)
     */
    protected HttpResponse discovery_userInteraction(String MSISDN, Map<String, String> authenticatorProperties, HttpServletResponse response)
            throws IOException {

        String url = MobileConnectAuthenticatorConstants.DISCOVERY_API_URL + "?" +
                MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_REDIRECT_URL + "=" +
                getCallbackUrl(authenticatorProperties);

        HttpGet httpGet = new HttpGet(url);

        httpGet.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_AUTHORIZATION, basicAuth);
        httpGet.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_ACCEPT, accept);
        HttpResponse urlResponse = connectURL_get(httpGet);

        response.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_AUTHORIZATION, basicAuth);
        response.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_ACCEPT, accept);
        response.sendRedirect(url);

        return urlResponse;

    }

    /**
     * IP Range based Discovery - When the Mobile Data Network is used by the App
     */
    protected HttpResponse discovery_ipRangeBased(String MSISDN, Map<String, String> authenticatorProperties, boolean cookie, boolean mobileData, String localIP, HttpServletResponse response)
            throws IOException {

        String url = MobileConnectAuthenticatorConstants.DISCOVERY_API_URL + "?" +
                MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_REDIRECT_URL + "=" +
                getCallbackUrl(authenticatorProperties) + "&"
                + MobileConnectAuthenticatorConstants.DISCOVERY_SET_COOKIES + "=" + String.valueOf(cookie) + "&"
                + MobileConnectAuthenticatorConstants.DISCOVERY_LOCAL_IP + "=" + localIP;

        HttpGet httpGet = new HttpGet(url);

        httpGet.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_AUTHORIZATION, basicAuth);
        httpGet.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_ACCEPT, accept);
        httpGet.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_USING_MOBILE_DATA, String.valueOf(mobileData));
        HttpResponse urlResponse = connectURL_get(httpGet);

        response.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_AUTHORIZATION, basicAuth);
        response.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_ACCEPT, accept);
        response.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_USING_MOBILE_DATA, String.valueOf(mobileData));
        response.sendRedirect(url);

        return urlResponse;

        //another step is required to be carried out

    }


    /**
     * Get the CallBackURL
     */
    protected String responseRedirect(String url, HttpServletResponse response, int status) {

        return MobileConnectAuthenticatorConstants.MOBILE_CONNECT_CALLBACK_URL;
    }

    /**
     * Get the CallBackURL
     */
    protected String getCallbackUrl(Map<String, String> authenticatorProperties) {

        if (StringUtils.isNotEmpty((String) authenticatorProperties.get(IdentityApplicationConstants.OAuth2.CALLBACK_URL))) {
            return (String) authenticatorProperties.get(IdentityApplicationConstants.OAuth2.CALLBACK_URL);
        }
        return MobileConnectAuthenticatorConstants.MOBILE_CONNECT_CALLBACK_URL;
    }


    public void buildClaims(AuthenticationContext context, String jsonObject)
            throws ApplicationAuthenticatorException {

        log.info("-------------Keet Build Claims-----------------");

        Map<String, Object> userClaims;
        userClaims = JSONUtils.parseJSON(jsonObject);
        if (userClaims != null) {
            Map<ClaimMapping, String> claims = new HashMap<ClaimMapping, String>();
            for (Map.Entry<String, Object> entry : userClaims.entrySet()) {
                claims.put(ClaimMapping.build(entry.getKey(), entry.getKey(), null,
                        false), entry.getValue().toString());
                if (log.isDebugEnabled() &&
                        IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.USER_CLAIMS)) {
                    log.debug("Adding claim mapping : " + entry.getKey() + " <> " + entry.getKey() + " : "
                            + entry.getValue());
                }
            }
            if (StringUtils.isBlank(context.getExternalIdP().getIdentityProvider().getClaimConfig().getUserClaimURI())) {
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

    private void setSubject(AuthenticationContext context, Map<String, Object> jsonObject)
            throws ApplicationAuthenticatorException {

        log.info("-------------Keet Set Subject-----------------");

        String authenticatedUserId = String.valueOf(jsonObject.get(MobileConnectAuthenticatorConstants.DEFAULT_USER_IDENTIFIER));

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

    @Override
    public String getFriendlyName() {
        return MobileConnectAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    public String getName() {
        return MobileConnectAuthenticatorConstants.AUTHENTICATOR_NAME;
    }

    /**
     * Get Configuration Properties
     */
    @Override
    public List<Property> getConfigurationProperties() {

        List<Property> configProperties = new ArrayList<Property>();

        Property mobileConnectKey = new Property();
        mobileConnectKey.setName(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_API_KEY);
        mobileConnectKey.setDisplayName("Mobile Connect Key");
        mobileConnectKey.setRequired(true);
        mobileConnectKey.setDescription("Enter the Mobile Connect Key of the Mobile Connect Application Account");
        mobileConnectKey.setDisplayOrder(0);
        configProperties.add(mobileConnectKey);

        Property mobileConnectSecret = new Property();
        mobileConnectSecret.setName(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_API_SECRET);
        mobileConnectSecret.setDisplayName("Mobile Connect Secret");
        mobileConnectSecret.setRequired(true);
        mobileConnectSecret.setConfidential(true);
        mobileConnectSecret.setDescription("Enter the Mobile Connect Secret of the Mobile Connect Application Account");
        mobileConnectSecret.setDisplayOrder(1);
        configProperties.add(mobileConnectSecret);

        Property callbackUrl = new Property();
        callbackUrl.setDisplayName("Callback URL");
        callbackUrl.setName(IdentityApplicationConstants.OAuth2.CALLBACK_URL);
        callbackUrl.setDescription("Enter the Callback URL");
        callbackUrl.setDisplayOrder(2);
        configProperties.add(callbackUrl);

        return configProperties;
    }
}
