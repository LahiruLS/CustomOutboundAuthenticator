package org.wso2.carbon.identity.application.authenticator.custom;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.basicauth.BasicAuthenticatorConstants;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.model.User;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;

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

        } else if (StringUtils.isNotEmpty(request.getParameter(CustomConstants.CODE))) { //if the user entered Otp code

            //this super.process() will call processAuthenticationResponse(), where the validation happens.
            return super.process(request, response, context);

        } else if ( //if the user already entered the email address (agent code or mobile number for the real case)
                /*StringUtils.isNotEmpty(request.getParameter(CustomConstants.AGENT_CODE))
                && StringUtils.isNotEmpty(request.getParameter(CustomConstants.MOBILE_NUMBER))*/
                StringUtils.isNotEmpty(request.getParameter("EMAIL_ADDRESS"))
        ) {
            initiateAuthenticationRequest(request, response, context);
            context.setCurrentAuthenticator(getName());
            return AuthenticatorFlowStatus.INCOMPLETE;

        } else { //if it's the first step:
            context.setProperty(CustomConstants.AUTH_STEP_KEY, CustomConstants.STEP_CODE_OR_MOBILE);
            initiateAuthenticationRequest(request, response, context);
            return AuthenticatorFlowStatus.INCOMPLETE;
            //return super.process(request, response, context);
        }


    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response, AuthenticationContext context) throws AuthenticationFailedException {

        context.setProperty(CustomConstants.AUTHENTICATION, CustomConstants.AUTHENTICATOR_NAME);
        String step = String.valueOf(context.getProperty(CustomConstants.AUTH_STEP_KEY));
        String loginPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL();
        String queryParams = context.getContextIdIncludedQueryParams();
        String redirectURL;

        if (Objects.nonNull(step)) {

            context.setProperty(CustomConstants.AGENT_BASED_AUTH_STATUS_KEY, "true");

            switch (step) {
                case CustomConstants.STEP_CODE_OR_MOBILE:
                    redirectURL = getEmailAddressRequestPage(context, getAuthenticatorConfig().getParameterMap())
                            + ("?" + queryParams)
                            + BasicAuthenticatorConstants.AUTHENTICATORS + getName();

                    try {

                        response.sendRedirect(redirectURL);

                    } catch (IOException e) {
                        throw new AuthenticationFailedException(e.getMessage(), User.getUserFromUserName(request.getParameter
                                (CustomConstants.AUTHENTICATOR_NAME)), e);
                    }
                    context.setProperty(CustomConstants.AUTH_STEP_KEY, CustomConstants.STEP_OTP);
                    break;
                case CustomConstants.STEP_OTP:

                    AuthenticatedUser authenticatedUser = getAgentDetails(context);
                    context.setSubject(authenticatedUser);

                    redirectURL = getOTPLoginPage(context, getAuthenticatorConfig().getParameterMap())
                            + ("?" + queryParams)
                            + BasicAuthenticatorConstants.AUTHENTICATORS + getName();

                    try {

                        response.sendRedirect(redirectURL);

                    } catch (IOException e) {
                        throw new AuthenticationFailedException(e.getMessage(), User.getUserFromUserName(request.getParameter
                                (CustomConstants.AUTHENTICATOR_NAME)), e);
                    }
                    context.setProperty(CustomConstants.AUTH_STEP_KEY, CustomConstants.STEP_DONE);
                    break;
            }
        }

    }

    private AuthenticatedUser getAgentDetails(AuthenticationContext context) {
        //here we should call to get agent details web service from client.

        return getAuthenticatedUser(context);

    }

    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response, AuthenticationContext context) throws AuthenticationFailedException {

        if (!validateOTP(request)) {
            throw new AuthenticationFailedException("OTP validation failed.");
        }

    }

    private AuthenticatedUser getAuthenticatedUser(AuthenticationContext context) {

        AuthenticatedUser authenticatedUser = null;
        Map<Integer, StepConfig> stepConfigMap = context.getSequenceConfig().getStepMap();
        for (StepConfig stepConfig : stepConfigMap.values()) {
            AuthenticatedUser authenticatedUserInStepConfig = stepConfig.getAuthenticatedUser();
            if (stepConfig.isSubjectAttributeStep() && authenticatedUserInStepConfig != null) {
                authenticatedUser = stepConfig.getAuthenticatedUser();
                break;
            }
        }
        return authenticatedUser;
    }

    private void processValidUserToken(AuthenticationContext context, AuthenticatedUser authenticatedUser) {

        context.setProperty(CustomConstants.CODE, StringUtils.EMPTY);
        context.setSubject(authenticatedUser);
    }

    private Boolean validateOTP(HttpServletRequest request) {
        //OTP client's validation web service must be called from here.
        //dummy validation:
        return request.getParameter(CustomConstants.CODE).equals("1234");
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

    private String getEmailAddressRequestPage(AuthenticationContext context, Map<String, String> parametersMap) {
        String emailAddressReqPage = null;
        String tenantDomain = context.getTenantDomain();
        Object propertiesFromLocal = context.getProperty(CustomConstants.GET_PROPERTY_FROM_REGISTRY);
        if ((propertiesFromLocal != null || tenantDomain.equals(CustomConstants.SUPER_TENANT)) &&
                parametersMap.containsKey(CustomConstants.EMAIL_ADDRESS_REQ_PAGE)) {
            emailAddressReqPage = parametersMap.get(CustomConstants.EMAIL_ADDRESS_REQ_PAGE);
        } else if ((context.getProperty(CustomConstants.EMAIL_ADDRESS_REQ_PAGE)) != null) {
            emailAddressReqPage = String.valueOf(context.getProperty(CustomConstants.EMAIL_ADDRESS_REQ_PAGE));
        }

        //variable is null -> check
        return "https://localhost:9443/emailotpauthenticationendpoint/emailAddress.jsp";
    }

}
