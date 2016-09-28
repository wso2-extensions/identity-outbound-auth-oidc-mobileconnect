package org.wso2.carbon.identity.authenticator.mobileconnect;

import org.apache.axiom.util.base64.Base64Utils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
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
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
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
public class MobileConnectAuthenticator extends OpenIDConnectAuthenticator implements FederatedApplicationAuthenticator {

    private static final long serialVersionUID = -6594339874626978804L;
    private static Log log = LogFactory.getLog(MobileConnectAuthenticator.class);

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

            //MobileConnectAuthenticatorConstants.MOBILE_CONNECT_FLOW_STATUS is the property set by the IDP, to keep track of the authentication process
            if (context.getProperty(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_FLOW_STATUS) == null) {

                //get the mobile connect key and secret
                String mobileConnectKey = getMobileConnectAPIKey(authenticatorProperties);
                String mobileConnectSecret = getMobileConnectAPISecret(authenticatorProperties);

                //delete this
                //msisdn = "+919205614966";

                //Base 64 encode the key and secret to attach as the header for URL connections
                String userpass = mobileConnectKey + ":" + mobileConnectSecret;
                String authorizationHeader = "Basic " + Base64Utils.encode(userpass.getBytes(StandardCharsets.UTF_8));

                //get the current state of the context to attach with the response
                String state = context.getContextIdentifier() + "," + MobileConnectAuthenticatorConstants.MOBILE_CONNECT_LOGIN_TYPE;
                state = getState(state, authenticatorProperties);

                try {
                    //carryout the process of connecting the Discovery Endpoint
                    discoveryEndpointConnect(authorizationHeader, msisdn, authenticatorProperties, context, state, response);
                } catch (JSONException e) {
                    //redirect to Log in retry URL
                    String url = ConfigurationFacade.getInstance().getAuthenticationEndpointRetryURL();
                    try {
                        response.sendRedirect(url);
                    } catch (IOException e1) {
                        throw new AuthenticationFailedException("response redirection failed", e1);
                    }
                }
            }

            if (MobileConnectAuthenticatorConstants.MOBILE_CONNECT_AUTHORIZATION_ENDPOINT.equals(context.getProperty(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_FLOW_STATUS))) {

                //decode the json object returned from the Discovery API
                JSONObject jsonObject = (JSONObject) context.getProperty(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_JSON_OBJECT);
                String authorizationEndpoint = "";
                String tokenEndpoint = "";
                String userinfoEndpoint = "";
                String operatoridScope = "";
                String authorizationClientId = "";
                String authorizationSecret = "";
                String subscriber_id = "";

                try {

                    JSONObject jsonResponse = jsonObject.getJSONObject(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_JSON_OBJECT);
                    authorizationClientId = jsonResponse.getString(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_AUTHORIZATION_CLIENT_ID);
                    authorizationSecret = jsonResponse.getString(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_AUTHORIZATION_CLIENT_SECRET);
                    subscriber_id = jsonResponse.getString(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_AUTHORIZATION_SUBSCRIBER_ID);
                    JSONObject apis = jsonResponse.getJSONObject(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_AUTHORIZATION_APIS);
                    JSONObject operatorid = apis.getJSONObject(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_AUTHORIZATION_OPERATOR_ID);

                    JSONArray operatoridLink = operatorid.getJSONArray(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_AUTHORIZATION_LINK);

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
                    } catch (IOException e1) {
                        throw new AuthenticationFailedException("response redirection failed. Invalid JSON object returned from the Discovery Server", e1);
                    }
                }

                //get scope from authentication Properties or from the response in the Discovery API
                String scope = getMobileConnectScope(authenticatorProperties, operatoridScope);
                //get acr values from the authentication properties
                String acr_values = authenticatorProperties.get(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_AUTHORIZATION_ACR_VALUES);
                //retrieve current state
                String state = context.getContextIdentifier() + "," + MobileConnectAuthenticatorConstants.MOBILE_CONNECT_LOGIN_TYPE;

                //create oAuthClientrequest to contact the Authorization Endpooint
                try {
                    OAuthClientRequest oAuthClientRequest = OAuthClientRequest
                            .authorizationLocation(authorizationEndpoint)
                            .setClientId(authorizationClientId)
                            .setRedirectURI(getCallbackUrl(authenticatorProperties))
                            .setResponseType(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_AUTHORIZATION_RESPONSE_TYPE)
                            .setScope(scope)
                            .setState(state)
                            .setParameter(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_AUTHORIZATION_ACR_VALUES, acr_values)
                            .setParameter(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_AUTHORIZATION_NONCE, state)
                            .setParameter(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_AUTHORIZATION_LOGIN_HINT, "ENCR_MSISDN:" + subscriber_id)
                            .buildQueryMessage();

                    //contact the authorization endpoint
                    String url = oAuthClientRequest.getLocationUri();
                    response.sendRedirect(url);

                    //set the context values to be used in the rest of the flow
                    context.setProperty(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_FLOW_STATUS, MobileConnectAuthenticatorConstants.MOBILE_CONNECT_TOKEN_ENDPOINT);
                    context.setProperty(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_TOKEN_ENDPOINT, tokenEndpoint);
                    context.setProperty(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_USERINFO_ENDPOINT, userinfoEndpoint);
                    context.setProperty(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_AUTHORIZATION_CLIENT_ID, authorizationClientId);
                    context.setProperty(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_AUTHORIZATION_CLIENT_SECRET, authorizationSecret);

                } catch (OAuthSystemException | IOException e) {
                    throw new AuthenticationFailedException("response redirection failed", e);
                }

            }

        } else {
            if (log.isDebugEnabled()) {
                log.debug("Error while retrieving properties. Authenticator Properties cannot be null");
            }
            throw new AuthenticationFailedException(" Authenticator Properties cannot be null");
        }

    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        //call this method to contact the tokenEndpoint and retrieve the token
        tokenAuthenticationRequest(request, context);

        //get jsonString object from the context
        String jsonObject = (String) context.getProperty(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_USER_INFO_RESPONSE);
        try {
            buildClaims(context, jsonObject);
        } catch (ApplicationAuthenticatorException e) {
            throw new AuthenticationFailedException("Authentication failed", e);
        }

    }


    /**
     * Carry out the discovery API endpoint connections
     */
    private void discoveryEndpointConnect(String basicAuth, String msisdn, Map<String, String> authenticatorProperties, AuthenticationContext context, String state,
                                          HttpServletResponse response) throws JSONException, AuthenticationFailedException {

        try {

            //call this method to retrieve a HttpURLConnection object
            HttpURLConnection connection = discoveryProcess(basicAuth, msisdn, authenticatorProperties, state);

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
                context.setProperty(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_FLOW_STATUS, MobileConnectAuthenticatorConstants.MOBILE_CONNECT_AUTHORIZATION_ENDPOINT);
                log.info("MSISDN is valid. Discovery Endpoint authorization successful");
            }
            //if 302, move temporarily
            else if (responseCode == 302) {
                String redirectUrl = connection.getHeaderField("location");
                response.sendRedirect(redirectUrl);
                context.setProperty(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_FLOW_STATUS, MobileConnectAuthenticatorConstants.MOBILE_CONNECT_AUTHORIZATION_ENDPOINT);
                log.info("MSISDN is invalid. Redirecting to mobile connect interface");
            }
            //if 401 unauthorized
            else if (responseCode == 401) {
                String url = ConfigurationFacade.getInstance().getAuthenticationEndpointRetryURL();
                response.sendRedirect(url);
                log.error("No Authorization or Bad Session");
            }
            //if 404, not found
            else if (responseCode == 404) {
                String url = ConfigurationFacade.getInstance().getAuthenticationEndpointRetryURL();
                response.sendRedirect(url);
                log.error("Bad MSISDN is supplied");
            }
            //if 400 bad request
            else if (responseCode == 400) {
                String url = ConfigurationFacade.getInstance().getAuthenticationEndpointRetryURL();
                response.sendRedirect(url);
                log.error("Bad MSISDN is supplied");
            }
        } catch (IOException e) {
            throw new AuthenticationFailedException("response redirection failed", e);
        }


    }


    /**
     * Return the mobile connect key from configuration files or UI
     */
    private String getMobileConnectAPIKey(Map<String, String> authenticatorProperties) throws AuthenticationFailedException {

        //retrieve mobile connect key from the configuration file of IS
        String mobileConnectKey = getAuthenticatorConfig().getParameterMap().get(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_KEY);

        if (StringUtils.isNotEmpty(mobileConnectKey)) {
            return mobileConnectKey;
        }

        //retrieve the mobile connect key from the IS user interface
        else if (StringUtils.isNotEmpty(authenticatorProperties.get(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_API_KEY))) {
            return authenticatorProperties.get(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_API_KEY);
        } else {

            //if both the configuration files and UI key values are null
            throw new AuthenticationFailedException("MobileConnect Key is not configured");
        }

    }


    /**
     * Return the mobile connect scope from UI or Discovery API response
     */
    private String getMobileConnectScope(Map<String, String> authenticatorProperties, String operatoridScope) throws AuthenticationFailedException {

        //retrieve mobile connect scope from the UI
        if (StringUtils.isNotEmpty(authenticatorProperties.get(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_AUTHORIZATION_SCOPE))) {
            return authenticatorProperties.get(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_AUTHORIZATION_SCOPE);
        }
        //retrieve the mobile connect scope from the discovery response
        else if (StringUtils.isNotEmpty(operatoridScope)) {
            return operatoridScope;
        } else {
            //if both the UI scope and Discovery response scope values are null
            throw new AuthenticationFailedException("MobileConnect Scope is not configured correctly");
        }

    }


    /**
     * Return the mobile connect secret from configuration files or UI
     */
    private String getMobileConnectAPISecret(Map<String, String> authenticatorProperties) throws AuthenticationFailedException {

        //retrieve mobile connect secret from the configuration file of IS
        String mobileConnectSecret = getAuthenticatorConfig().getParameterMap().get(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_SECRET);
        if (StringUtils.isNotEmpty(mobileConnectSecret)) {
            return mobileConnectSecret;
        }
        //retrieve the mobile connect secret from the IS user interface
        else if (StringUtils.isNotEmpty(authenticatorProperties.get(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_API_SECRET))) {
            return authenticatorProperties.get(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_API_SECRET);
        } else {
            //if both the configuration files and UI secret values are null
            throw new AuthenticationFailedException("MobileConnect Secret is not configured");
        }

    }


    /**
     * Process the response of the Discovery and Mobile Connect API and contact the Token Endpoint
     */
    private void tokenAuthenticationRequest(HttpServletRequest request,
                                            AuthenticationContext context)
            throws AuthenticationFailedException {


        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();

        //get the following values from the context of the flow
        String tokenEndpoint = (String) context.getProperty(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_TOKEN_ENDPOINT);
        String authorizationClientId = (String) context.getProperty(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_AUTHORIZATION_CLIENT_ID);
        String authorizationSecret = (String) context.getProperty(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_AUTHORIZATION_CLIENT_SECRET);

        try {

            String redirect_URL = getCallbackUrl(authenticatorProperties);
            String code = request.getParameter(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_TOKEN_CODE);

            OAuthClientRequest oAuthClientRequest = OAuthClientRequest.tokenLocation(tokenEndpoint)
                    .setGrantType(GrantType.AUTHORIZATION_CODE)
                    .setClientId(authorizationSecret)
                    .setClientSecret(authorizationClientId)
                    .setRedirectURI(redirect_URL)
                    .setCode(code)
                    .buildBodyMessage();

            //Base 64 encode the key and secret to attach as the header for URL connections
            String userpass = authorizationClientId + ":" + authorizationSecret;
            String authorizationHeader = "Basic " + Base64Utils.encode(userpass.getBytes(StandardCharsets.UTF_8));

            //attach headers to the oAuthClientRequest
            oAuthClientRequest.setHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_AUTHORIZATION, authorizationHeader);
            oAuthClientRequest.setHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_TOKEN_CONTENT_TYPE, MobileConnectAuthenticatorConstants.MOBILE_CONNECT_TOKEN_CONTENT_TYPE_VALUE);
            OAuthClient oAuthClient = new OAuthClient(new URLConnectionClient());

            //get response from the Token Endpoint
            OAuthClientResponse oAuthResponse = oAuthClient.accessToken(oAuthClientRequest);

            //retrieve data from the response
            String accessToken = oAuthResponse.getParam(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_ACCESS_TOKEN);

            //call the userinfoAuthenticationRequest to retrive user information
            userInfoAuthenticationRequest(accessToken, context);


        } catch (OAuthSystemException | OAuthProblemException e) {
            throw new AuthenticationFailedException("Token andpoint authentication failed", e);
        }


    }

    /**
     * Access the userinfo Endpoint and using the access_token
     */
    private void userInfoAuthenticationRequest(String accessTokenIdentifier, AuthenticationContext context) throws AuthenticationFailedException {

        try {

            //retrieve the userinfo endpoint url from the Context
            String url = (String) context.getProperty(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_USERINFO_ENDPOINT);

            HttpGet httpGet = new HttpGet(url);
            String tokenValue = "Bearer " + accessTokenIdentifier;

            //add header values required
            httpGet.addHeader(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_DISCOVERY_AUTHORIZATION, tokenValue);

            //connect to the userinfo endpoint
            HttpResponse urlResponse = connectURL_get(httpGet);

            BufferedReader rd = new BufferedReader(new InputStreamReader(urlResponse.getEntity().getContent()));
            String jsonString = "";

            String line;
            while ((line = rd.readLine()) != null) {
                jsonString += line + "\n";
            }
            //set the jsonString object in the context
            context.setProperty(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_USER_INFO_RESPONSE, jsonString);

        } catch (IOException e) {
            throw new AuthenticationFailedException("Authentication Error when contacting the userinfo endpoint", e);
        }

    }


    /**
     * Execute the URL Get request
     */
    private HttpResponse connectURL_get(HttpGet request)
            throws IOException {

        //execute the HttpGet request and return a HttpResponse
        CloseableHttpClient client = HttpClientBuilder.create().build();
        return client.execute(request);

    }

    /**
     * msisdn based Discovery (Developer app uses Discovery API to send msisdn)
     */
    private HttpURLConnection discoveryProcess(String authorizationHeader, String msisdn, Map<String, String> authenticatorProperties, String state)
            throws IOException {

        //check whether the msisdn is provided as a parameter
        if (StringUtils.isNotEmpty(msisdn)) {
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
                    MobileConnectAuthenticatorConstants.MOBILE_CONNECT_SESSION_DATA_KEY + "=" + state + "&"
                    + MobileConnectAuthenticatorConstants.MOBILE_CONNECT_MANUAL_SELECTION + "=" + String.valueOf(true);

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
     * Build the claims required to follow up the process
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

    /**
     * Set the subject of the Authenticator in the context
     */
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

    /**
     * Get the Friendly Name of the Authenticator
     */
    @Override
    public String getFriendlyName() {
        return MobileConnectAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    /**
     * Get the Name of the Authenticator
     */
    @Override
    public String getName() {
        return MobileConnectAuthenticatorConstants.AUTHENTICATOR_NAME;
    }

    /**
     * Get the CallBackURL
     */
    @Override
    protected String getCallbackUrl(Map<String, String> authenticatorProperties) {

        if (StringUtils.isNotEmpty(authenticatorProperties.get(IdentityApplicationConstants.OAuth2.CALLBACK_URL))) {
            return authenticatorProperties.get(IdentityApplicationConstants.OAuth2.CALLBACK_URL);
        }
        return MobileConnectAuthenticatorConstants.MOBILE_CONNECT_CALLBACK_URL;
    }

    /**
     * Get Configuration Properties
     */
    @Override
    public List<Property> getConfigurationProperties() {

        List<Property> configProperties = new ArrayList<>();

        //set the mobile connect key input field
        Property mobileConnectKey = new Property();
        mobileConnectKey.setName(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_API_KEY);
        mobileConnectKey.setDisplayName("Mobile Connect Key");
        mobileConnectKey.setRequired(false);
        mobileConnectKey.setDescription("Enter the Mobile Connect Key of the Mobile Connect Application Account");
        mobileConnectKey.setDisplayOrder(0);
        configProperties.add(mobileConnectKey);

        //set the mobile connect secret input field
        Property mobileConnectSecret = new Property();
        mobileConnectSecret.setName(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_API_SECRET);
        mobileConnectSecret.setDisplayName("Mobile Connect Secret");
        mobileConnectSecret.setRequired(false);
        mobileConnectSecret.setConfidential(true);
        mobileConnectSecret.setDescription("Enter the Mobile Connect Secret of the Mobile Connect Application Account");
        mobileConnectSecret.setDisplayOrder(1);
        configProperties.add(mobileConnectSecret);

        //set the mobile connect scope input field
        Property mobileConnectScope = new Property();
        mobileConnectScope.setName(MobileConnectAuthenticatorConstants.MOBILE_CONNECT_AUTHORIZATION_SCOPE);
        mobileConnectScope.setDisplayName("Mobile Connect Scope");
        mobileConnectScope.setRequired(true);
        mobileConnectScope.setValue("openid");
        mobileConnectScope.setDescription("Enter the Mobile Connect Scope Required");
        mobileConnectScope.setDisplayOrder(2);
        configProperties.add(mobileConnectScope);

        //set the mobile connect arc values
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
