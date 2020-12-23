package org.wso2.carbon.identity.application.authenticator.custom.test;

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
        return "TEST";
    }

    public String getName() {
        return "TEST CUSTOM AUTHENTICATOR";
    }

    public String getFriendlyName() {
        return "TEST CUSTOM AUTHENTICATOR";
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
        List<Property> configProperties = new ArrayList<Property>();

        Property clientId = new Property();
        clientId.setName("TEST 1");
        clientId.setDisplayName("TEST 1");
        clientId.setRequired(true);
        clientId.setDescription("TEST");
        configProperties.add(clientId);

        Property clientSecret = new Property();
        clientSecret.setName("TEST 2");
        clientSecret.setDisplayName("TEST 2");
        clientSecret.setRequired(true);
        clientSecret.setConfidential(true);
        clientSecret.setDescription("TEST 2");
        configProperties.add(clientSecret);

        return configProperties;
    }
}
