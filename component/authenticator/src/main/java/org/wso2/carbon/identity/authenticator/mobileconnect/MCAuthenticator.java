package org.wso2.carbon.identity.authenticator.mobileconnect;

import org.apache.axiom.util.base64.Base64Utils;
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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Authenticator of Mobile Connect.
 * The MobileConnectAuthenticator class carries out the Discovery API Process and the Mobile Connect API process
 */
public class MCAuthenticator extends OpenIDConnectAuthenticator implements FederatedApplicationAuthenticator {

    private static Log log = LogFactory.getLog(MCAuthenticator.class);

    /**
     * Initiate the Authentication request when the AuthenticatorFlowStatus is INCOMPLETE
     */
    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context)
            throws AuthenticationFailedException {

        //check whether the msisdn is sent by the service provider
        String msisdn = request.getParameter("msisdn");

        //retrieve the properties configured 
        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();

        //this is null, if no such properties are defined in the IS as an IDP
        if (authenticatorProperties != null) {

            //"Flowstatus" is the property set by the IDP, to keep track of the authentication process
            if (context.getProperty("flowStatus") == null) {

                //get the mobile connect key and secret
                String mobileConnectKey = getMobileConnectAPIKey(authenticatorProperties);
                String mobileConnectSecret = getMobileConnectAPISecret(authenticatorProperties);

                //delete this
                msisdn = "+919205614966";

                //Base 64 encode the key and secret to attach as the header for URL connections
                String userpass = mobileConnectKey + ":" + mobileConnectSecret;
                String authorizationHeader = "Basic " + Base64Utils.encode(userpass.getBytes(StandardCharsets.UTF_8));

                //get the current state of the context to attach with the response
                String state = context.getContextIdentifier() + "," + MobileConnectAuthenticatorConstants.MOBILE_CONNECT_LOGIN_TYPE;
                state = getState(state, authenticatorProperties);

                try {
                    //carryout the discovery process
                    discoveryEndpointConnect(authorizationHeader, msisdn, authenticatorProperties, context, state, request, response);
                } catch (IOException | JSONException e) {
                    e.printStackTrace();
                }
            }

            if (context.getProperty("flowStatus").equals("authorizationEndpoint")) {

                JSONObject jsonObject = (JSONObject) context.getProperty(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_JSON_OBJECT);
                String authorizationEndpoint = "";
                String tokenEndpoint = "";
                String userinfoEndpoint = "";
                String operatoridScope = "";
                String authorizationClientId = "";
                String authorizationSecret = "";
                String subscriber_id = "";
                String serving_operator = "";
                String country = "";
                String currency = "";

                try {

                    String ttl = jsonObject.getString("ttl");

                    JSONObject jsonResponse = jsonObject.getJSONObject("response");
                    authorizationClientId = jsonResponse.getString("client_id");
                    authorizationSecret = jsonResponse.getString("client_secret");
                    subscriber_id = jsonResponse.getString("subscriber_id");
                    serving_operator = jsonResponse.getString("serving_operator");
                    country = jsonResponse.getString("country");
                    currency = jsonResponse.getString("currency");

                    JSONObject apis = jsonResponse.getJSONObject("apis");
                    JSONObject operatorid = apis.getJSONObject("operatorid");

                    JSONArray operatoridLink = operatorid.getJSONArray("link");

                    for (int i = 0; i < operatoridLink.length(); i++) {
                        String linkRef = operatoridLink.getJSONObject(i).getString("rel");
                        if (linkRef.equals("authorization")) {
                            authorizationEndpoint = operatoridLink.getJSONObject(i).getString("href");
                        }
                        if (linkRef.equals("token")) {
                            tokenEndpoint = operatoridLink.getJSONObject(i).getString("href");
                        }
                        if (linkRef.equals("userinfo")) {
                            userinfoEndpoint = operatoridLink.getJSONObject(i).getString("href");
                        }
                        if (linkRef.equals("scope")) {
                            operatoridScope = operatoridLink.getJSONObject(i).getString("href");
                        }
                    }


                } catch (JSONException e) {
                    e.printStackTrace();
                }

                //remove these when u get the proper access points
                //authorizationClientId = MobileConnectAuthenticatorConstants.MOBILE_CONNECT_API_KEY_VALUE;
                //authorizationEndpoint = "https://localhost:9444/oauth2/authorize";

                String scope = authenticatorProperties.get(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_AUTHORIZATION_SCOPE);
                String acr_values = authenticatorProperties.get(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_AUTHORIZATION_ACR_VALUES);

                String state = context.getContextIdentifier() + "," + MobileConnectAuthenticatorConstants.MOBILE_CONNECT_LOGIN_TYPE;

                try {
                    OAuthClientRequest authzRequest = OAuthClientRequest
                            .authorizationLocation(authorizationEndpoint)
                            .setClientId(authorizationClientId)
                            .setRedirectURI(getCallbackUrl(authenticatorProperties))
                            .setResponseType("code")
                            .setScope(scope)
                            .setState(state)
                            .setParameter(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_AUTHORIZATION_ACR_VALUES, acr_values)
                            .setParameter(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_AUTHORIZATION_NONCE, state)
                            .setParameter("login_hint", "ENCR_MSISDN:" + subscriber_id)
                            .buildQueryMessage();

                    String url = authzRequest.getLocationUri();
                    response.sendRedirect(url);
                    request.getSession().setAttribute("canHandleStatus", "incomplete");

                    context.setProperty("flowStatus", "tokenEndpoint");
                    context.setProperty("tokenEndpoint", tokenEndpoint);
                    context.setProperty("userinfoEndpoint", userinfoEndpoint);
                    context.setProperty("authorizationClientId", authorizationClientId);
                    context.setProperty("authorizationSecret", authorizationSecret);

                } catch (OAuthSystemException e) {
                    e.printStackTrace();
                } catch (IOException e) {
                    e.printStackTrace();
                }

            }

        } else {
            if (log.isDebugEnabled()) {
                log.debug("Error while retrieving properties. Authenticator Properties cannot be null");
            }
            throw new AuthenticationFailedException(" Authenticator Properties cannot be null");
        }

    }

    /**
     * Carry out the discovery API endpoint connections
     */
    protected void discoveryEndpointConnect(String basicAuth, String MSISDN, Map<String, String> authenticatorProperties, AuthenticationContext context, String state,
                                            HttpServletRequest request, HttpServletResponse response) throws IOException, JSONException {

        //this variable will hold the response from the connections
        HttpURLConnection connection = null;
        //call this method to retrieve a HttpURLConnection object
        connection = discoveryProcess(basicAuth, MSISDN, authenticatorProperties, state);

        //check the responseCode of the HttpURLConnection
        int responseCode = connection.getResponseCode();

        //if 200 OK
        if (responseCode == 200) {
            //read the response sent by the server
            BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            StringBuilder stringBuilder = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                stringBuilder.append(line);
            }
            String responseString = stringBuilder.toString();
            reader.close();
            JSONObject jsonObject = new JSONObject(responseString);
            context.setProperty(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_JSON_OBJECT, jsonObject);
            context.setProperty("flowStatus", "authorizationEndpoint");
            log.info("MSISDN is valid. Discovery Endpoint authorization successful");
        }
        //if 302, move temporarily
        else if (responseCode==302) {
            String redirectUrl = connection.getHeaderField("location");
            response.sendRedirect(redirectUrl);
            context.setProperty("flowStatus", "authorizationEndpoint");
            log.info("MSISDN is invalid. Redirecting to mobile connect interface");
        }
        //if 401 unauthorized
        else if(responseCode == 401){
            String url = ConfigurationFacade.getInstance().getAuthenticationEndpointRetryURL();
                response.sendRedirect(url);
                log.error("No Authorization or Bad Session");
        }
        //if 404, not found
        else if(responseCode == 404){
                String url = ConfigurationFacade.getInstance().getAuthenticationEndpointRetryURL();
                response.sendRedirect(url);
                log.error("Bad MSISDN is supplied");
        }
        //if 400 bad request
        else if(responseCode == 400){
                String url = ConfigurationFacade.getInstance().getAuthenticationEndpointRetryURL();
                response.sendRedirect(url);
                log.error("Bad MSISDN is supplied");
        }


    }


    /**
     * Return the mobile connect key from configuration files or UI
     */
    protected String getMobileConnectAPIKey(Map<String, String> authenticatorProperties) throws AuthenticationFailedException {

        //retrieve mobile connect key from the configuration file of IS
        String mobileConnectKey = getAuthenticatorConfig().getParameterMap().get(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_KEY);

        if (mobileConnectKey != null) {
            return mobileConnectKey;
        }

        //retrieve the mobile connect key from the IS user interface
        else if (authenticatorProperties.get(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_API_KEY) != null) {
            return authenticatorProperties.get(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_API_KEY);
        } else {

            //if both the configuration files and UI key values are null
            throw new AuthenticationFailedException("MobileConnect Key is not configured");
        }

    }


    /**
     * Return the mobile connect secret from configuration files or UI
     */
    protected String getMobileConnectAPISecret(Map<String, String> authenticatorProperties) throws AuthenticationFailedException {

        //retrieve mobile connect secret from the configuration file of IS
        String mobileConnectSecret = getAuthenticatorConfig().getParameterMap().get(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_SECRET);
        if (mobileConnectSecret != null) {
            return mobileConnectSecret;
        }
        //retrieve the mobile connect secret from the IS user interface
        else if (authenticatorProperties.get(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_API_SECRET) != null) {
            return authenticatorProperties.get(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_API_SECRET);
        } else {
            //if both the configuration files and UI secret values are null
            throw new AuthenticationFailedException("MobileConnect Secret is not configured");
        }

    }

    /**
     * Process the response of the Discovery and Mobile Connect API
     */
    protected void tokenAuthenticationRequest(HttpServletRequest request,
                                              HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();

        String tokenEndpoint = (String) context.getProperty("tokenEndpoint");
        String authorizationClientId = (String) context.getProperty("authorizationClientId");
        String authorizationSecret = (String) context.getProperty("authorizationSecret");

        try {

            //remove these assignments once the API is connected
            String redirect_URL = getCallbackUrl(authenticatorProperties);
            //tokenEndpoint = "https://localhost:9444/oauth2/token";
            //authorizationClientId = "TTFFTDnbB5piYvQCMSApLmY9RDka";
            //authorizationSecret = "CijTuPz1hd3rormpV1IrCcbW5xQa";
            String code = request.getParameter("code");

            OAuthClientRequest accessRequest = OAuthClientRequest.tokenLocation(tokenEndpoint)
                    .setGrantType(GrantType.AUTHORIZATION_CODE)
                    .setClientId(authorizationSecret)
                    .setClientSecret(authorizationClientId)
                    .setRedirectURI(redirect_URL)
                    .setCode(code)
                    .buildBodyMessage();

            String userpass = authorizationClientId + ":" + authorizationSecret;

            String basicAuth = "Basic " + javax.xml.bind.DatatypeConverter.printBase64Binary(userpass.getBytes("UTF-8"));

            //uncomment these two after proper implementations
            //accessRequest.setHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_AUTHORIZATION, basicAuth);
            //accessRequest.setHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_TOKEN_CONTENT_TYPE, MobileConnectAuthenticatorConstants.MOBILE_CONNECT_TOKEN_CONTENT_TYPE_VALUE);

            OAuthClient oAuthClient = new OAuthClient(new URLConnectionClient());

            OAuthClientResponse oAuthResponse = oAuthClient.accessToken(accessRequest);
            String accessToken = oAuthResponse.getParam("access_token");
            userinfoAuthenticationresponse(accessToken, response, context);

        } catch (OAuthSystemException | UnsupportedEncodingException | OAuthProblemException e) {
            e.printStackTrace();
        }


    }

    protected void userinfoAuthenticationresponse(String accessTokenIdentifier, HttpServletResponse response, AuthenticationContext context) {

        HttpResponse urlResponse = null;
        try {
            urlResponse = userinfoEndpoint_Access(accessTokenIdentifier);
            BufferedReader rd = new BufferedReader(new InputStreamReader(urlResponse.getEntity().getContent()));
            String jsonData = "";

            String line = "";
            while ((line = rd.readLine()) != null) {
                jsonData += line + "\n";
            }
            context.setProperty("jsonObject", jsonData);

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
    protected HttpResponse discoveryMCCMNC_get(String basicAuth, String MNC, String MCC, Map<String, String> authenticatorProperties, HttpServletResponse response, boolean manualSelection, String sessionDK)
            throws IOException {

        String url = MobileConnectAuthenticatorConstants.DISCOVERY_API_URL + "?"
                + MobileConnectAuthenticatorConstants.DISCOVERY_IDENTIFIED_MCC + "=" + MCC + "&"
                + MobileConnectAuthenticatorConstants.DISCOVERY_IDENTIFIED_MNC + "=" + MNC + "&"
                + MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_REDIRECT_URL + "=" +
                getCallbackUrl(authenticatorProperties) + "&"
                + MobileConnectAuthenticatorConstants.MOBILE_CONNECT_MANUAL_SELECTION + "=" + String.valueOf(manualSelection) + "&" +
                MobileConnectAuthenticatorConstants.MOBILE_CONNECT_COMMONAUTH_SDK + "=" + sessionDK;

        if (manualSelection) {
            response.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_AUTHORIZATION, basicAuth);
            response.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_ACCEPT, MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_ACCEPT_VALUE);
            response.sendRedirect(url);
            return null;
        }

        HttpGet httpGet = new HttpGet(url);

        httpGet.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_AUTHORIZATION, basicAuth);
        httpGet.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_ACCEPT, MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_ACCEPT_VALUE);

        HttpResponse urlResponse = connectURL_get(httpGet);

        return urlResponse;

    }

    /**
     * MCC / MNC Discovery with POST verb
     */
    protected HttpResponse discoveryMCCMNC_post(String basicAuth, String MNC, String MCC, Map<String, String> authenticatorProperties, HttpServletResponse response, boolean manualSelection)
            throws IOException {

        String url = MobileConnectAuthenticatorConstants.DISCOVERY_API_URL + "&"
                + MobileConnectAuthenticatorConstants.MOBILE_CONNECT_MANUAL_SELECTION + "=" + String.valueOf(manualSelection);

        if (manualSelection) {
            response.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_AUTHORIZATION, basicAuth);
            response.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_ACCEPT, MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_ACCEPT_VALUE);
            response.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_CONTENT_TYPE, MobileConnectAuthenticatorConstants.MOBILE_CONNECT_TOKEN_CONTENT_TYPE_VALUE);
            response.addHeader(MobileConnectAuthenticatorConstants.DISCOVERY_IDENTIFIED_MCC, MCC);
            response.addHeader(MobileConnectAuthenticatorConstants.DISCOVERY_IDENTIFIED_MNC, MNC);
            response.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_REDIRECT_URL, getCallbackUrl(authenticatorProperties));
            response.sendRedirect(url);
            return null;
        }
        ;

        HttpPost httpPost = new HttpPost(url);

        httpPost.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_AUTHORIZATION, basicAuth);
        httpPost.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_ACCEPT, MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_ACCEPT_VALUE);
        httpPost.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_CONTENT_TYPE, MobileConnectAuthenticatorConstants.MOBILE_CONNECT_TOKEN_CONTENT_TYPE_VALUE);
        httpPost.addHeader(MobileConnectAuthenticatorConstants.DISCOVERY_IDENTIFIED_MCC, MCC);
        httpPost.addHeader(MobileConnectAuthenticatorConstants.DISCOVERY_IDENTIFIED_MNC, MNC);
        httpPost.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_REDIRECT_URL, getCallbackUrl(authenticatorProperties));
        HttpResponse urlResponse = connectURL_post(httpPost);


        return urlResponse;

    }

    /**
     * Discovery request with Ignore Cookies flag - MCC/MNC Request
     */
    protected HttpResponse discoveryMCCMNC_ignoreCookies(String basicAuth, String MNC, String MCC, Map<String, String> authenticatorProperties, boolean cookie, HttpServletResponse response, boolean manualSelection)
            throws IOException {

        String url = MobileConnectAuthenticatorConstants.DISCOVERY_API_URL + "?"
                + MobileConnectAuthenticatorConstants.DISCOVERY_IDENTIFIED_MCC + "=" + MCC + "&"
                + MobileConnectAuthenticatorConstants.DISCOVERY_IDENTIFIED_MNC + "=" + MNC + "&"
                + MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_REDIRECT_URL + "=" +
                getCallbackUrl(authenticatorProperties) + "&"
                + MobileConnectAuthenticatorConstants.DISCOVERY_IGNORE_COOKIES + "=" + String.valueOf(cookie) + "&"
                + MobileConnectAuthenticatorConstants.MOBILE_CONNECT_MANUAL_SELECTION + "=" + String.valueOf(manualSelection);

        if (manualSelection) {
            response.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_AUTHORIZATION, basicAuth);
            response.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_ACCEPT, MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_ACCEPT_VALUE);
            response.sendRedirect(url);
            return null;
        }


        HttpGet httpGet = new HttpGet(url);

        httpGet.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_AUTHORIZATION, basicAuth);
        httpGet.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_ACCEPT, MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_ACCEPT_VALUE);
        HttpResponse urlResponse = connectURL_get(httpGet);


        return urlResponse;

    }

    /**
     * Discovery request with Ignore Cookes flag: MSISDN Based POST request
     */
    protected HttpResponse discoveryMSISDN_ignoreCookies(String basicAuth, String MSISDN, Map<String, String> authenticatorProperties, boolean cookie, HttpServletResponse response, boolean manualSelection)
            throws IOException {

        String url = MobileConnectAuthenticatorConstants.DISCOVERY_API_URL + "?" +
                MobileConnectAuthenticatorConstants.DISCOVERY_IGNORE_COOKIES + "=" + String.valueOf(cookie) + "&"
                + MobileConnectAuthenticatorConstants.MOBILE_CONNECT_MANUAL_SELECTION + "=" + String.valueOf(manualSelection);

        if (manualSelection) {
            response.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_AUTHORIZATION, basicAuth);
            response.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_ACCEPT, MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_ACCEPT_VALUE);
            response.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_CONTENT_TYPE, MobileConnectAuthenticatorConstants.MOBILE_CONNECT_TOKEN_CONTENT_TYPE_VALUE);
            response.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_MSISDN, MSISDN);
            response.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_REDIRECT_URL, getCallbackUrl(authenticatorProperties));
            response.sendRedirect(url);
            return null;
        }

        HttpPost httpPost = new HttpPost(url);

        httpPost.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_AUTHORIZATION, basicAuth);
        httpPost.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_ACCEPT, MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_ACCEPT_VALUE);
        httpPost.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_CONTENT_TYPE, MobileConnectAuthenticatorConstants.MOBILE_CONNECT_TOKEN_CONTENT_TYPE_VALUE);
        httpPost.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_MSISDN, MSISDN);
        httpPost.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_REDIRECT_URL, getCallbackUrl(authenticatorProperties));
        HttpResponse urlResponse = connectURL_post(httpPost);


        return urlResponse;

    }

    /**
     * Discovery request with Set-Cookies=false
     */
    protected HttpResponse discoveryMCCMNC_setCookies(String basicAuth, String MNC, String MCC, Map<String, String> authenticatorProperties, boolean cookie, HttpServletResponse response, boolean manualSelection)
            throws IOException {

        String url = MobileConnectAuthenticatorConstants.DISCOVERY_API_URL + "?"
                + MobileConnectAuthenticatorConstants.DISCOVERY_IDENTIFIED_MCC + "=" + MCC + "&"
                + MobileConnectAuthenticatorConstants.DISCOVERY_IDENTIFIED_MNC + "=" + MNC + "&"
                + MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_REDIRECT_URL + "=" +
                getCallbackUrl(authenticatorProperties) + "&"
                + MobileConnectAuthenticatorConstants.DISCOVERY_SET_COOKIES + "=" + String.valueOf(cookie) + "&"
                + MobileConnectAuthenticatorConstants.MOBILE_CONNECT_MANUAL_SELECTION + "=" + String.valueOf(manualSelection);

        if (manualSelection) {
            response.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_AUTHORIZATION, basicAuth);
            response.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_ACCEPT, MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_ACCEPT_VALUE);
            response.sendRedirect(url);
            return null;
        }
        HttpGet httpGet = new HttpGet(url);

        httpGet.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_AUTHORIZATION, basicAuth);
        httpGet.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_ACCEPT, MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_ACCEPT_VALUE);
        HttpResponse urlResponse = connectURL_get(httpGet);


        return urlResponse;

    }

    /**
     * MSISDN based Discovery (Developer app uses Discovery API to send MSISDN)
     */
    protected String discoveryNoMSISDN(String authorizationHeader, String MSISDN, Map<String, String> authenticatorProperties, HttpServletResponse response, boolean manualSelection, String sessionDK)
            throws IOException {

        String url = MobileConnectAuthenticatorConstants.DISCOVERY_API_URL + "?" +
                MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_REDIRECT_URL + "=" + getCallbackUrl(authenticatorProperties);

        URL obj = new URL(url);
        HttpURLConnection connection = (HttpURLConnection) obj.openConnection();

        connection.setRequestMethod("POST");
        connection.setRequestProperty(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_CONTENT_TYPE, MobileConnectAuthenticatorConstants.MOBILE_CONNECT_TOKEN_CONTENT_TYPE_VALUE);
        connection.setRequestProperty(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_AUTHORIZATION, authorizationHeader);
        connection.setRequestProperty(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_ACCEPT, MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_ACCEPT_VALUE);
        connection.setDoOutput(true);

        String data = "MSISDN=%2B" + MSISDN.substring(1) + "&Redirect_URL=" + getCallbackUrl(authenticatorProperties);
        OutputStreamWriter out = new OutputStreamWriter(connection.getOutputStream());
        out.write(data);
        out.close();


        BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
        StringBuilder out2 = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            out2.append(line);
        }
        String response2 = out2.toString();
        System.out.println(response2);   //Prints the string content read from input stream

        reader.close();
        return response2;

//                + "&"
//                + MobileConnectAuthenticatorConstants.MOBILE_CONNECT_MANUAL_SELECTION + "=" + String.valueOf(manualSelection);
//        if (manualSelection) {
//            response.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_AUTHORIZATION, basicAuth);
//            response.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_ACCEPT, MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_ACCEPT_VALUE);
//            response.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_CONTENT_TYPE, MobileConnectAuthenticatorConstants.MOBILE_CONNECT_TOKEN_CONTENT_TYPE_VALUE);
//            response.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_MSISDN, MSISDN);
//            response.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_REDIRECT_URL, getCallbackUrl(authenticatorProperties));
//            response.sendRedirect(url);
//            return null;
//        }
//        HttpPost httpPost = new HttpPost(url);
//
//        httpPost.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_AUTHORIZATION, basicAuth);
//        httpPost.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_ACCEPT, MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_ACCEPT_VALUE);
//        httpPost.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_CONTENT_TYPE, MobileConnectAuthenticatorConstants.MOBILE_CONNECT_TOKEN_CONTENT_TYPE_VALUE);
//        httpPost.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_MSISDN, MSISDN);
//        httpPost.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_REDIRECT_URL, getCallbackUrl(authenticatorProperties));
//        HttpResponse urlResponse = connectURL_post(httpPost);
//
//
//        return urlResponse;

    }

    /**
     * msisdn based Discovery (Developer app uses Discovery API to send msisdn)
     */
    protected HttpURLConnection discoveryProcess(String authorizationHeader, String msisdn, Map<String, String> authenticatorProperties, String state)
            throws IOException {

        //check whether the msisdn is provided as a parameter
        if (msisdn != null) {
            String url = MobileConnectAuthenticatorConstants.DISCOVERY_API_URL + "?" +
                    MobileConnectAuthenticatorConstants.MOBILE_CONNECT_SESSION_DATA_KEY + "=" + state;

            URL obj = new URL(url);
            HttpURLConnection connection = (HttpURLConnection) obj.openConnection();

            connection.setRequestMethod("POST");
            connection.setRequestProperty(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_CONTENT_TYPE, MobileConnectAuthenticatorConstants.MOBILE_CONNECT_TOKEN_CONTENT_TYPE_VALUE);
            connection.setRequestProperty(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_AUTHORIZATION, authorizationHeader);
            connection.setRequestProperty(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_ACCEPT, MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_ACCEPT_VALUE);
            connection.setDoOutput(true);

            //send the data with the connection. remove the plus sign (+) from the msisdn value
            String data = "MSISDN=%2B" + msisdn.substring(1) + "&Redirect_URL=" + getCallbackUrl(authenticatorProperties);
            OutputStreamWriter out = new OutputStreamWriter(connection.getOutputStream());
            out.write(data);
            out.close();

            return connection;
        }
        //if msisdn is null - not provided by the service provider
        else {

            String url = MobileConnectAuthenticatorConstants.DISCOVERY_API_URL + "?" +
                    MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_REDIRECT_URL + "=" + getCallbackUrl(authenticatorProperties) + "&" +
                    MobileConnectAuthenticatorConstants.MOBILE_CONNECT_SESSION_DATA_KEY + "=" + state;

            URL obj = new URL(url);
            HttpURLConnection connection = (HttpURLConnection) obj.openConnection();

            connection.setRequestMethod("GET");
            connection.setRequestProperty(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_AUTHORIZATION, authorizationHeader);
            connection.setRequestProperty(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_ACCEPT, MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_ACCEPT_VALUE);
            connection.setDoOutput(true);

            return connection;
        }

    }

    /**
     * MSISDN Based Discovery (Followed after user interaction)
     */
    protected HttpResponse discovery_userInteraction(String basicAuth, String MSISDN, Map<String, String> authenticatorProperties, HttpServletResponse response, boolean manualSelection)
            throws IOException {

        String url = MobileConnectAuthenticatorConstants.DISCOVERY_API_URL + "?" +
                MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_REDIRECT_URL + "=" +
                getCallbackUrl(authenticatorProperties) + "&"
                + MobileConnectAuthenticatorConstants.MOBILE_CONNECT_MANUAL_SELECTION + "=" + String.valueOf(manualSelection);


        if (manualSelection) {
            response.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_AUTHORIZATION, basicAuth);
            response.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_ACCEPT, MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_ACCEPT_VALUE);
            response.sendRedirect(url);
            return null;
        }

        HttpGet httpGet = new HttpGet(url);

        httpGet.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_AUTHORIZATION, basicAuth);
        httpGet.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_ACCEPT, MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_ACCEPT_VALUE);
        HttpResponse urlResponse = connectURL_get(httpGet);


        return urlResponse;

    }

    /**
     * IP Range based Discovery - When the Mobile Data Network is used by the App
     */
    protected HttpResponse discovery_ipRangeBased(String basicAuth, String MSISDN, Map<String, String> authenticatorProperties, boolean cookie, boolean mobileData, String localIP, HttpServletResponse response, boolean manualSelection)
            throws IOException {

        String url = MobileConnectAuthenticatorConstants.DISCOVERY_API_URL + "?" +
                MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_REDIRECT_URL + "=" +
                getCallbackUrl(authenticatorProperties) + "&"
                + MobileConnectAuthenticatorConstants.DISCOVERY_SET_COOKIES + "=" + String.valueOf(cookie) + "&"
                + MobileConnectAuthenticatorConstants.DISCOVERY_LOCAL_IP + "=" + localIP + "&"
                + MobileConnectAuthenticatorConstants.MOBILE_CONNECT_MANUAL_SELECTION + "=" + String.valueOf(manualSelection);

        if (manualSelection) {
            response.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_AUTHORIZATION, basicAuth);
            response.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_ACCEPT, MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_ACCEPT_VALUE);
            response.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_USING_MOBILE_DATA, String.valueOf(mobileData));
            response.sendRedirect(url);
            return null;
        }

        HttpGet httpGet = new HttpGet(url);

        httpGet.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_AUTHORIZATION, basicAuth);
        httpGet.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_ACCEPT, MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_ACCEPT_VALUE);
        httpGet.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_USING_MOBILE_DATA, String.valueOf(mobileData));
        HttpResponse urlResponse = connectURL_get(httpGet);


        return urlResponse;

        //another step is required to be carried out

    }

    public void buildClaims(AuthenticationContext context, String jsonObject)
            throws ApplicationAuthenticatorException {

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
     * Get the CallBackURL
     */
    @Override
    protected String getCallbackUrl(Map<String, String> authenticatorProperties) {

        if (StringUtils.isNotEmpty((String) authenticatorProperties.get(IdentityApplicationConstants.OAuth2.CALLBACK_URL))) {
            return (String) authenticatorProperties.get(IdentityApplicationConstants.OAuth2.CALLBACK_URL);
        }
        return MobileConnectAuthenticatorConstants.MOBILE_CONNECT_CALLBACK_URL;
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
        mobileConnectKey.setRequired(false);
        mobileConnectKey.setDescription("Enter the Mobile Connect Key of the Mobile Connect Application Account");
        mobileConnectKey.setDisplayOrder(0);
        configProperties.add(mobileConnectKey);

        Property mobileConnectSecret = new Property();
        mobileConnectSecret.setName(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_API_SECRET);
        mobileConnectSecret.setDisplayName("Mobile Connect Secret");
        mobileConnectSecret.setRequired(false);
        mobileConnectSecret.setConfidential(true);
        mobileConnectSecret.setDescription("Enter the Mobile Connect Secret of the Mobile Connect Application Account");
        mobileConnectSecret.setDisplayOrder(1);
        configProperties.add(mobileConnectSecret);

        Property mobileConnectScope = new Property();
        mobileConnectScope.setName(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_AUTHORIZATION_SCOPE);
        mobileConnectScope.setDisplayName("Mobile Connect Scope");
        mobileConnectScope.setRequired(true);
        mobileConnectScope.setValue("openid");
        mobileConnectScope.setDescription("Enter the Mobile Connect Scope Required");
        mobileConnectScope.setDisplayOrder(2);
        configProperties.add(mobileConnectScope);

        Property mobileConnectAcrValues = new Property();
        mobileConnectAcrValues.setName(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_AUTHORIZATION_ACR_VALUES);
        mobileConnectAcrValues.setDisplayName("Mobile Connect ACR Values");
        mobileConnectAcrValues.setRequired(true);
        mobileConnectAcrValues.setValue("1");
        mobileConnectAcrValues.setDescription("Enter the Mobile Connect ACR Values required");
        mobileConnectAcrValues.setDisplayOrder(3);
        configProperties.add(mobileConnectAcrValues);

        return configProperties;
    }
}
