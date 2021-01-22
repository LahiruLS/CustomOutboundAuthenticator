<%@ page import="org.owasp.encoder.Encode" %>
<%@ page import="org.wso2.carbon.identity.application.authentication.endpoint.util.Constants" %>
<%@ page import="java.io.File" %>
<%@ page import="java.util.Map" %>
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt" %>
<%@ include file="includes/localize.jsp" %>

<fmt:bundle
        basename="org.wso2.carbon.identity.application.authentication.endpoint.i18n.Resources">
    <%
        request.getSession().invalidate();
        String queryString = request.getQueryString();
        Map<String, String> idpAuthenticatorMapping = null;
        if (request.getAttribute(Constants.IDP_AUTHENTICATOR_MAP) != null) {
            idpAuthenticatorMapping = (Map<String, String>) request
                    .getAttribute(Constants.IDP_AUTHENTICATOR_MAP);
        }
        
        String errorMessage = "Authentication Failed! Please Retry";
        String authenticationFailed = "false";
        
        if (Boolean.parseBoolean(request.getParameter(Constants.AUTH_FAILURE))) {
            authenticationFailed = "true";
            
            if (request.getParameter(Constants.AUTH_FAILURE_MSG) != null) {
                errorMessage = request.getParameter(Constants.AUTH_FAILURE_MSG);
                
                if (errorMessage.equalsIgnoreCase("authentication.fail.message")) {
                    errorMessage = "Authentication Failed! Please Retry";
                }
            }
        }
    %>
    
    <html>
    <head>
        <!-- header -->
        <%
            File headerFile = new File(getServletContext().getRealPath("extensions/header.jsp"));
            if (headerFile.exists()) {
        %>
        <jsp:include page="extensions/header.jsp"/>
        <%
        } else {
        %>
        <jsp:directive.include file="includes/header.jsp"/>
        <%
            }
        %>
        
        <!--[if lt IE 9]>
        <script src="js/html5shiv.min.js"></script>
        <script src="js/respond.min.js"></script>
        <![endif]-->
    </head>
    
    <body onload="getLoginDiv()">
    <main class="center-segment">
        <div class="ui container medium center aligned middle aligned">
            <!-- product-title -->
            <%
                File productTitleFile = new File(getServletContext().getRealPath("extensions/product-title.jsp"));
                if (productTitleFile.exists()) {
            %>
            <jsp:include page="extensions/product-title.jsp"/>
            <%
            } else {
            %>
            <jsp:directive.include file="includes/product-title.jsp"/>
            <%
                }
            %>
            
            <div class="ui segment">
                <!-- page content -->
                <h2>Enter your agent code or mobile number</h2>
                <div class="ui divider hidden"></div>
                <%
                    if ("true".equals(authenticationFailed)) {
                %>
                <div class="ui negative message" id="failed-msg"><%=Encode.forHtmlContent(errorMessage)%>
                </div>
                <div class="ui divider hidden"></div>
                <%
                    }
                %>
                <%
                    if ("true".equals(authenticationFailed)) {
                %>
                <div class="ui negative message" id="failed-msg"><%=Encode.forHtmlContent(errorMessage)%>
                </div>
                <div class="ui divider hidden"></div>
                <%
                    }
                %>
                <div id="alertDiv"></div>
                <div class="segment-form">
                    <form class="ui large form" id="pin_form" name="pin_form"
                          action="../../commonauth" method="POST">
                        
                        <%
                            String loginFailed = request.getParameter("authFailure");
                            if (loginFailed != null && "true".equals(loginFailed)) {
                                String authFailureMsg = request.getParameter("authFailureMsg");
                                if (authFailureMsg != null && "login.fail.message".equals(authFailureMsg)) {
                        %>
                        <div class="ui negative message">Authentication Failed!
                            Please Retry
                        </div>
                        <div class="ui divider hidden"></div>
                        <%
                                }
                            }
                        %>
                        
                        <div class="field">
                            <label for="password"></label> <input type="text"
                                                                  id='AGENT_CODE_OR_MOBILE' name="AGENT_CODE_OR_MOBILE"
                                                                  size='30'/>
                        </div>
                        <input type="hidden" name="sessionDataKey"
                               value='<%=Encode.forHtmlAttribute(request.getParameter("sessionDataKey"))%>'/>
                        <div class="ui divider hidden"></div>
                        <div class="align-right buttons">
                            <input type="button" name="update" id="update" value="Send"
                                   class="ui primary button">
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </main>
    
    <!-- product-footer -->
    <%
        File productFooterFile = new File(getServletContext().getRealPath("extensions/product-footer.jsp"));
        if (productFooterFile.exists()) {
    %>
    <jsp:include page="extensions/product-footer.jsp"/>
    <%
    } else {
    %>
    <jsp:directive.include file="includes/product-footer.jsp"/>
    <%
        }
    %>
    
    <!-- footer -->
    <%
        File footerFile = new File(getServletContext().getRealPath("extensions/footer.jsp"));
        if (footerFile.exists()) {
    %>
    <jsp:include page="extensions/footer.jsp"/>
    <%
    } else {
    %>
    <jsp:directive.include file="includes/footer.jsp"/>
    <%
        }
    %>
    
    <script type="text/javascript">
        $(document).ready(function () {
            $('#update').click(function () {
                var emailAddress = document
                    .getElementById("AGENT_CODE_OR_MOBILE").value;
                if (emailAddress == "") {
                    document.getElementById('alertDiv').innerHTML
                        = '<div id="error-msg" class="ui negative message">Please enter the emailAddress!</div>'
                        + '<div class="ui divider hidden"></div>';
                } else {
                    $('#pin_form').submit();
                }
            });
        });
    </script>
    </body>
    </html>
</fmt:bundle>
