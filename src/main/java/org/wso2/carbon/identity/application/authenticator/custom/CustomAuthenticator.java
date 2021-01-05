package org.wso2.carbon.identity.application.authenticator.custom;

import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.common.model.Property;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.ArrayList;
import java.util.List;

public class CustomAuthenticator extends AbstractApplicationAuthenticator implements FederatedApplicationAuthenticator {

    protected void processAuthenticationResponse(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationContext authenticationContext) throws AuthenticationFailedException {

    }

    public boolean canHandle(HttpServletRequest httpServletRequest) {
        return true;
    }

    public String getContextIdentifier(HttpServletRequest httpServletRequest) {

        return httpServletRequest.getParameter(CustomConstants.SESSION_DATA_KEY);

    }

    public String getName() {
        return "Test name for custom authenticator";
    }

    public String getFriendlyName() {
        return "Test friendly name for custom authenticator";
    }

    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request, HttpServletResponse response, AuthenticationContext context) throws AuthenticationFailedException, LogoutFailedException {
        return super.process(request, response, context);
    }

    @Override
    protected void initiateLogoutRequest(HttpServletRequest request, HttpServletResponse response, AuthenticationContext context) throws LogoutFailedException {
        super.initiateLogoutRequest(request, response, context);
    }

    @Override
    protected void processLogoutResponse(HttpServletRequest request, HttpServletResponse response, AuthenticationContext context) throws LogoutFailedException {
        super.processLogoutResponse(request, response, context);
    }

    @Override
    public List<Property> getConfigurationProperties() {
        List<Property> configProperties = new ArrayList<>();

        Property testProperty1 = new Property();
        testProperty1.setName("Test name 1");
        testProperty1.setDisplayName("Test display name 1");
        testProperty1.setRequired(true);
        testProperty1.setDescription("Test description 1");
        configProperties.add(testProperty1);

        Property testProperty2 = new Property();
        testProperty2.setName("Test name 2");
        testProperty2.setDisplayName("Test display name 2");
        testProperty2.setRequired(true);
        testProperty2.setConfidential(true);
        testProperty2.setDescription("Test description 2");
        configProperties.add(testProperty2);

        return configProperties;
    }
}
