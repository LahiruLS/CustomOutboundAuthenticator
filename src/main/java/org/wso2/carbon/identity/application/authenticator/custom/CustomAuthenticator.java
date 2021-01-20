package org.wso2.carbon.identity.application.authenticator.custom;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authenticator.basicauth.BasicAuthenticatorConstants;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.model.User;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class CustomAuthenticator extends AbstractApplicationAuthenticator implements FederatedApplicationAuthenticator {

    private static final Log log = LogFactory.getLog(CustomAuthenticator.class);

    /**
     * Specifies whether this authenticator can handle the authentication response.
     *
     * @param request
     * @return
     */
    public boolean canHandle(HttpServletRequest request) {

        return true;

    }

    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request, HttpServletResponse response, AuthenticationContext context) throws AuthenticationFailedException, LogoutFailedException {
        // if the logout request comes, then no need to go through and complete the flow.
        if (context.isLogoutRequest()) {
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        } else if (StringUtils.isNotEmpty(request.getParameter(CustomConstants.AGENT_CODE))
                || StringUtils.isNotEmpty(request.getParameter(CustomConstants.MOBILE_NUMBER))) {
            // if the request comes with EMAIL ADDRESS, it will go through this flow.
            initiateAuthenticationRequest(request, response, context);
            return AuthenticatorFlowStatus.INCOMPLETE;
        } else if (StringUtils.isNotEmpty(request.getParameter(CustomConstants.CODE))) {
            AuthenticatorFlowStatus authenticatorFlowStatus = super.process(request, response, context);
            //doSomeOTPValidationStuff();
            return authenticatorFlowStatus;
        } else {
            initiateAuthenticationRequest(request, response, context);
            return AuthenticatorFlowStatus.INCOMPLETE;
            //return super.process(request, response, context);
        }


    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response, AuthenticationContext context) throws AuthenticationFailedException {

        context.setProperty(CustomConstants.AUTHENTICATION, CustomConstants.AUTHENTICATOR_NAME);
        //As start, we will be using wso2-is login page instead client's one.
        String loginPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL();
        String queryParams = context.getContextIdIncludedQueryParams();

        String redirectURL = loginPage + ("?" + queryParams)
                + BasicAuthenticatorConstants.AUTHENTICATORS + getName();

        try {

            response.sendRedirect(getOTPLoginPage(context, getAuthenticatorConfig().getParameterMap()));

        } catch (IOException e) {
            throw new AuthenticationFailedException(e.getMessage(), User.getUserFromUserName(request.getParameter
                    (CustomConstants.AUTHENTICATOR_NAME)), e);
        }


    }

    protected void processAuthenticationResponse(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationContext authenticationContext) throws AuthenticationFailedException {

        /*
        The client's Web Services for agent validation and
        OTP must be called from here, after user has entered the credentials.
         */

    }

    @Override
    public List<Property> getConfigurationProperties() {

        //This list will be shown in the UI. Two sample properties were loaded to show each text field position.
        List<Property> configProperties = new ArrayList<>();

        Property redirectUrl = new Property();
        redirectUrl.setName("redirectUrl");
        redirectUrl.setDisplayName("Redirect URL");
        redirectUrl.setRequired(true);
        redirectUrl.setDescription("The URL where the login request will be redirected to");
        redirectUrl.setType("string");
        redirectUrl.setDisplayOrder(1);
        configProperties.add(redirectUrl);

        Property callBackUrl = new Property();
        callBackUrl.setName("otpPageUrl");
        callBackUrl.setDisplayName("OTP submission page Url");
        callBackUrl.setRequired(true);
        callBackUrl.setDescription("The URL where the OTP submission request will be redirected to");
        callBackUrl.setType("string");
        callBackUrl.setDisplayOrder(2);
        configProperties.add(callBackUrl);

        return configProperties;
    }

    /**
     * Returns a unique identifier that will map the authentication request and the response.
     * The value returned by the invocation of authentication request and the response should be the same.
     *
     * @param httpServletRequest
     * @return
     */
    public String getContextIdentifier(HttpServletRequest httpServletRequest) {

        return httpServletRequest.getParameter(CustomConstants.SESSION_DATA_KEY);

    }

    public String getName() {
        return CustomConstants.AUTHENTICATOR_NAME;
    }

    public String getFriendlyName() {
        return CustomConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    /**
     * Redirect the user to agent details request page where user has to
     * enter either the agent ID or the mobile number and submit.
     *
     * @param response    the HttpServletResponse
     * @param context     the AuthenticationContext
     * @param queryParams the queryParams
     * @throws AuthenticationFailedException
     */
    private void redirectToAgentDetailsReqPage(HttpServletResponse response, AuthenticationContext context,
                                               Map<String, String> authenticatorParameters, String queryParams)
            throws AuthenticationFailedException {
        String agentDetailsReqPage = getAgentDetailsReqPage(context, authenticatorParameters);
        try {
            String url = getRedirectURL(agentDetailsReqPage, queryParams);
            response.sendRedirect(url);
        } catch (IOException e) {
            throw new AuthenticationFailedException("Authentication failed!. An IOException was caught while " +
                    "redirecting to agent details  request page. ", e);
        }
    }

    /**
     * To get the redirection URL.
     *
     * @param baseURI     the base path
     * @param queryParams the queryParams
     * @return url
     */
    private String getRedirectURL(String baseURI, String queryParams) {
        String url;
        if (StringUtils.isNotEmpty(queryParams)) {
            url = baseURI + "?" + queryParams + "&" + CustomConstants.AUTHENTICATORS + getName();
        } else {
            url = baseURI + "?" + CustomConstants.AUTHENTICATORS + getName();
        }
        return url;
    }

    private String getOTPLoginPage(AuthenticationContext context, Map<String, String> authenticatorParameters) {

        return "https://localhost:9443/emailotpauthenticationendpoint/emailotp.jsp";
    }

    private String getAgentDetailsReqPage(AuthenticationContext context, Map<String, String> emailOTPParameters) {

        return " ";
    }

}
