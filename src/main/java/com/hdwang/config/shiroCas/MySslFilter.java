package com.hdwang.config.shiroCas;

import org.apache.shiro.web.filter.authz.SslFilter;
import org.apache.shiro.web.util.WebUtils;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;

public class MySslFilter extends SslFilter {

    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response, Object mappedValue) {
        try {
            if (super.isAccessAllowed(request, response, mappedValue)) {
                request.isSecure();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    @Override
    protected void redirectToLogin(ServletRequest request, ServletResponse response) throws IOException
    {
        WebUtils.issueRedirect(request, response, "http://localhost/home");
    }

}
