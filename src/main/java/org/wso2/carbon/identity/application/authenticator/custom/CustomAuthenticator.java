package org.wso2.carbon.identity.application.authenticator.custom;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
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

        String agentCode = request.getParameter(CustomConstants.AGENT_CODE);
        String mobileNumber = request.getParameter(CustomConstants.MOBILE_NUMBER);
        return agentCode != null || mobileNumber != null;

    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response, AuthenticationContext context) throws AuthenticationFailedException {

        Map<String, String> parameterMap = getAuthenticatorConfig().getParameterMap();
        String redirectURL = parameterMap.get("redirect");
        try {

            response.sendRedirect(redirectURL);

        } catch (IOException e) {
            throw new AuthenticationFailedException(e.getMessage(), User.getUserFromUserName(request.getParameter
                    (CustomConstants.AUTHENTICATOR_NAME)), e);
        }
    }

    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request, HttpServletResponse response, AuthenticationContext context) throws AuthenticationFailedException, LogoutFailedException {
        return super.process(request, response, context);
    }

    protected void processAuthenticationResponse(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationContext authenticationContext) throws AuthenticationFailedException {

        /*
        The client's Web Services for agent validation and
        OTP must be called from here, after user has entered the credentials.
         */

    }

    @Override
    protected void initiateLogoutRequest(HttpServletRequest request, HttpServletResponse response, AuthenticationContext context) throws LogoutFailedException {

    }

    @Override
    protected void processLogoutResponse(HttpServletRequest request, HttpServletResponse response, AuthenticationContext context) throws LogoutFailedException {

    }

    @Override
    public List<Property> getConfigurationProperties() {

        //This list will be shown in the UI. Two sample properties were loaded to show each text field position.

        List<Property> configProperties = new ArrayList<>();

        Property RedirectUrl = new Property();
        RedirectUrl.setName("redirect");
        RedirectUrl.setDisplayName("Redirect URL");
        RedirectUrl.setRequired(true);
        RedirectUrl.setDescription("The URL where the login request will be redirected to");
        configProperties.add(RedirectUrl);

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
}
