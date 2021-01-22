package org.wso2.carbon.identity.application.authenticator.custom;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
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

        } else if (StringUtils.isNotEmpty(request.getParameter(CustomConstants.CODE)) //if the user entered Otp code
                && checkStep(CustomConstants.STEP_OTP_SENT, context)) {

            //this super.process() will call processAuthenticationResponse(), where the validation happens.
            return super.process(request, response, context);

        } else if ( //if the user already entered the code or mobile number
                StringUtils.isNotEmpty(request.getParameter(CustomConstants.AGENT_CODE_OR_MOBILE))
                        && checkStep(CustomConstants.STEP_OTP, context)
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

    private boolean checkStep(String step, AuthenticationContext context) {
        return step.equals(String.valueOf(context.getProperty(CustomConstants.AUTH_STEP_KEY)));
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response, AuthenticationContext context) throws AuthenticationFailedException {

        context.setProperty(CustomConstants.AUTHENTICATION, CustomConstants.AUTHENTICATOR_NAME);
        String step = String.valueOf(context.getProperty(CustomConstants.AUTH_STEP_KEY));
        String queryParams = context.getContextIdIncludedQueryParams();
        String redirectURL;

        if (Objects.nonNull(step)) {

            switch (step) {
                case CustomConstants.STEP_CODE_OR_MOBILE:
                    redirectURL = getRedirectURL(getAgentDetailsReqPage(context, context.getAuthenticatorProperties()), queryParams);

                    try {

                        response.sendRedirect(redirectURL);
                        context.setProperty(CustomConstants.AUTH_STEP_KEY, CustomConstants.STEP_OTP);

                    } catch (IOException e) {
                        throw new AuthenticationFailedException(e.getMessage(), User.getUserFromUserName(request.getParameter
                                (CustomConstants.AUTHENTICATOR_NAME)), e);
                    }
                    break;
                case CustomConstants.STEP_OTP:

                    AuthenticatedUser authenticatedUser = getAgentDetails(context);
                    context.setSubject(authenticatedUser);

                    redirectURL = getRedirectURL(getOTPLoginPage(context, context.getAuthenticatorProperties()), queryParams);

                    try {
                        generateOtpCode(request, context);
                        //TODO OTP Code must be sent from here through the client's SMS web service.
                        response.sendRedirect(redirectURL);

                        context.setProperty(CustomConstants.AUTH_STEP_KEY, CustomConstants.STEP_OTP_SENT);
                    } catch (IOException e) {
                        throw new AuthenticationFailedException(e.getMessage(), User.getUserFromUserName(request.getParameter
                                (CustomConstants.AUTHENTICATOR_NAME)), e);
                    }
                    break;
            }
        }

    }

    private AuthenticatedUser getAgentDetails(AuthenticationContext context) {
        //TODO here we should call to get agent details web service from client, instead of below call.
        return getAuthenticatedUser(context);

    }

    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response, AuthenticationContext context) throws AuthenticationFailedException {

        if (!validateOTP(request, context)) {

            throw new AuthenticationFailedException("OTP validation failed.");
        }

        context.setProperty(CustomConstants.CODE, StringUtils.EMPTY);

    }

    private AuthenticatedUser getAuthenticatedUser(AuthenticationContext context) {
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier("test");
        authenticatedUser.setUserName("ramiro");
        authenticatedUser.setFederatedUser(true);
        return authenticatedUser;
    }


    private Boolean validateOTP(HttpServletRequest request, AuthenticationContext context) throws AuthenticationFailedException {
        String userToken = request.getParameter(CustomConstants.CODE);
        String contextToken = (String) context.getProperty(CustomConstants.OTP_TOKEN);
        long generatedTime = (long) context.getProperty(CustomConstants.OTP_GENERATED_TIME);
        boolean isExpired = isExpired(generatedTime, context);

        if (userToken.equals(contextToken) && !isExpired) {
            context.setProperty(CustomConstants.CODE_MISMATCH, false);
            return true;
        }

        return false;
    }

    @Override
    public List<Property> getConfigurationProperties() {

        //This list will be shown in the UI. Two sample properties were loaded to show each text field position.
        List<Property> configProperties = new ArrayList<>();

        Property redirectUrl = new Property();
        redirectUrl.setName(CustomConstants.PROPERTY_REDIRECT_NAME);
        redirectUrl.setDisplayName(CustomConstants.PROPERTY_OTP_DISPLAY_NAME);
        redirectUrl.setRequired(true);
        redirectUrl.setDescription(CustomConstants.PROPERTY_REDIRECT_DESCRIPTION);
        redirectUrl.setType(CustomConstants.PROPERTY_STRING_TYPE);
        redirectUrl.setDisplayOrder(1);
        configProperties.add(redirectUrl);

        Property callBackUrl = new Property();
        callBackUrl.setName(CustomConstants.PROPERTY_OTP_NAME);
        callBackUrl.setDisplayName(CustomConstants.PROPERTY_OTP_DISPLAY_NAME);
        callBackUrl.setRequired(true);
        callBackUrl.setDescription(CustomConstants.PROPERTY_OTP_DESCRIPTION);
        callBackUrl.setType(CustomConstants.PROPERTY_STRING_TYPE);
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

    private String getOTPLoginPage(AuthenticationContext context, Map<String, String> parameterMap) {
        return parameterMap.get(CustomConstants.OTP_PAGE_URL);
        //return "https://localhost:9443/smsotpauthenticationendpoint/smsotp.jsp";
    }

    private String getAgentDetailsReqPage(AuthenticationContext context, Map<String, String> parameterMap) {
        return parameterMap.get(CustomConstants.REDIRECT_URL);
        //"https://localhost:9443/emailotpauthenticationendpoint/custom-agent-code.jsp";
    }

    /**
     * Checks whether otp is Expired or not.
     *
     * @param generatedTime : Email OTP generated time
     * @param context       : the Authentication Context
     */
    protected boolean isExpired(long generatedTime, AuthenticationContext context)
            throws AuthenticationFailedException {

        Long expireTime;
        try {
            expireTime = Long.valueOf(getExpireTime(context));
        } catch (NumberFormatException e) {
            throw new AuthenticationFailedException("Invalid Email OTP expiration time configured.");
        }
        if (expireTime == -1) {
            if (log.isDebugEnabled()) {
                log.debug("Email OTP configured not to expire.");
            }
            return false;
        } else if (System.currentTimeMillis() < generatedTime + expireTime) {
            return false;
        } else {
            return true;
        }
    }

    /**
     * A method to get Expire Time configuration from EmailOTPUtils.
     *
     * @param context :  AuthenticationContext
     */
    private String getExpireTime(AuthenticationContext context) {

        String expireTime = getAuthenticatorConfig().getParameterMap().get(CustomConstants.OTP_CODE_EXPIRE_TIME);
        if (StringUtils.isEmpty(expireTime)) {
            expireTime = CustomConstants.OTP_EXPIRE_TIME_DEFAULT;
            if (log.isDebugEnabled()) {
                log.debug("OTP Expiration Time not specified default value will be used");
            }
        }
        return expireTime;
    }

    private void generateOtpCode(HttpServletRequest request, AuthenticationContext context) {
        OneTimePassword token = new OneTimePassword();
        String secret = OneTimePassword.getRandomNumber(CustomConstants.SECRET_KEY_LENGTH);
        String myToken = token.generateToken(secret, "" + CustomConstants.NUMBER_BASE
                , CustomConstants.NUMBER_DIGIT);

        context.setProperty(CustomConstants.OTP_TOKEN, myToken);
        context.setProperty(CustomConstants.OTP_GENERATED_TIME, System.currentTimeMillis());
        context.setProperty(CustomConstants.OTP_EXPIRED, "false");
    }
}
