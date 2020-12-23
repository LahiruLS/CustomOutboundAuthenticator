package org.wso2.carbon.identity.application.authenticator.custom.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.application.authenticator.custom.test.CustomAuthenticator;

import java.util.Hashtable;

/**
 * @scr.component name="org.wso2.carbon.identity.application.authenticator.custom.test.component" immediate="true"
 */
public class CustomAuthenticatorServiceComponent {
    private static final Log LOGGER = LogFactory.getLog(CustomAuthenticatorServiceComponent.class);

    protected void activate(ComponentContext ctxt) {
        try {
            CustomAuthenticator customAuthenticator = new CustomAuthenticator();
            Hashtable<String, String> props = new Hashtable<String, String>();
            ctxt.getBundleContext().registerService(ApplicationAuthenticator.class.getName(), customAuthenticator, props);

            LOGGER.info("----Custom Authenticator bundle is activated----");

        } catch (Throwable e) {
            LOGGER.fatal("----Error while activating Custom authenticator----", e);
        }
    }

    protected void deactivate(ComponentContext ctxt) {
        LOGGER.info("----Custom Authenticator bundle is deactivated----");
    }
}
