package org.wso2.sample.outbound.authenticator.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.*;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.sample.outbound.authenticator.CustomAuthenticator;
import org.wso2.carbon.user.core.service.RealmService;

@Component(name = "carbon.identity.application.authenticator.custom.component", immediate = true)
public class CustomAuthenticatorServiceComponent {
    private static final Log log = LogFactory.getLog(CustomAuthenticatorServiceComponent.class);
    private static RealmService realmService;

    public static RealmService getRealmService() {

        return realmService;
    }

    @Reference(
            name = "realm.service",
            service = RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService"
    )
    protected void setRealmService(RealmService realmService) {

        log.debug("Setting the Realm Service");
        CustomAuthenticatorServiceComponent.realmService = realmService;
    }

    @Activate
    protected void activate(ComponentContext ctxt) {

        try {
            CustomAuthenticator customAuthenticator = new CustomAuthenticator();
            ctxt.getBundleContext().registerService(ApplicationAuthenticator.class.getName(), customAuthenticator, null);
            if (log.isDebugEnabled()) {
                log.info("Sample Identifier bundle is activated");
            }
        } catch (Throwable e) {
            log.error("Sample Identifier Authenticator bundle activation Failed", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext ctxt) {

        if (log.isDebugEnabled()) {
            log.info("Sample Identifier bundle is deactivated");
        }
    }

    protected void unsetRealmService(RealmService realmService) {

        log.debug("UnSetting the Realm Service");
        CustomAuthenticatorServiceComponent.realmService = null;
    }
}
