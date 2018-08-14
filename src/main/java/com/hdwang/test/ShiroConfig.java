//package com.hdwang.test;
//
//import java.util.HashMap;
//import java.util.LinkedHashMap;
//import java.util.Map;
//import javax.servlet.Filter;
//import org.apache.shiro.cache.ehcache.EhCacheManager;
//import org.apache.shiro.cas.CasFilter;
//import org.apache.shiro.codec.Base64;
//import org.apache.shiro.mgt.SecurityManager;
//import org.apache.shiro.spring.LifecycleBeanPostProcessor;
//import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor;
//import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
//import org.apache.shiro.web.mgt.CookieRememberMeManager;
//import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
//import org.apache.shiro.web.servlet.SimpleCookie;
//import org.jasig.cas.client.session.SingleSignOutFilter;
//import org.jasig.cas.client.session.SingleSignOutHttpSessionListener;
//import org.springframework.beans.factory.annotation.Qualifier;
//import org.springframework.beans.factory.annotation.Value;
//import org.springframework.boot.web.servlet.FilterRegistrationBean;
//import org.springframework.boot.web.servlet.ServletListenerRegistrationBean;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import com.ruoyi.common.utils.StringUtils;
//import com.ruoyi.framework.shiro.realm.UserRealm;
//import com.ruoyi.framework.shiro.session.OnlineSessionDAO;
//import com.ruoyi.framework.shiro.session.OnlineSessionFactory;
//import com.ruoyi.framework.shiro.web.filter.LogoutFilter;
//import com.ruoyi.framework.shiro.web.filter.captcha.CaptchaValidateFilter;
//import com.ruoyi.framework.shiro.web.filter.online.OnlineSessionFilter;
//import com.ruoyi.framework.shiro.web.filter.sync.SyncOnlineSessionFilter;
//import com.ruoyi.framework.shiro.web.session.OnlineWebSessionManager;
//import com.ruoyi.framework.shiro.web.session.SpringSessionValidationScheduler;
//import at.pollux.thymeleaf.shiro.dialect.ShiroDialect;
//import org.springframework.web.filter.DelegatingFilterProxy;
//
///**
// * 权限配置加载
// *
// * @author ruoyi
// */
//@Configuration
//public class ShiroConfig
//{
//    public static final String PREMISSION_STRING = "perms[\"{0}\"]";
//
//    // Session超时时间，单位为毫秒（默认30分钟）
//    @Value("${shiro.session.expireTime}")
//    private int expireTime;
//
//    // 相隔多久检查一次session的有效性，单位毫秒，默认就是10分钟
//    @Value("${shiro.session.validationInterval}")
//    private int validationInterval;
//
//    // 验证码开关
//    @Value("${shiro.user.captchaEbabled}")
//    private boolean captchaEbabled;
//
//    // 验证码类型
//    @Value("${shiro.user.captchaType}")
//    private String captchaType;
//
//    // 设置Cookie的域名
//    @Value("${shiro.cookie.domain}")
//    private String domain;
//
//    // 设置cookie的有效访问路径
//    @Value("${shiro.cookie.path}")
//    private String path;
//
//    // 设置HttpOnly属性
//    @Value("${shiro.cookie.httpOnly}")
//    private boolean httpOnly;
//
//    // 设置Cookie的过期时间，秒为单位
//    @Value("${shiro.cookie.maxAge}")
//    private int maxAge;
//
//    // 登录地址
//    @Value("${shiro.user.loginUrl}")
//    private String loginUrl;
//
//    // 权限认证失败地址
//    @Value("${shiro.user.unauthorizedUrl}")
//    private String unauthorizedUrl;
//
//    /**
//     * 缓存管理器 使用Ehcache实现
//     */
//    @Bean
//    public EhCacheManager getEhCacheManager()
//    {
//        net.sf.ehcache.CacheManager cacheManager = net.sf.ehcache.CacheManager.getCacheManager("ruoyi");
//        EhCacheManager em = new EhCacheManager();
//        if (StringUtils.isNull(cacheManager))
//        {
//            em.setCacheManagerConfigFile("classpath:ehcache/ehcache-shiro.xml");
//            return em;
//        }
//        else
//        {
//            em.setCacheManager(cacheManager);
//            return em;
//        }
//    }
//
////    /**
////     * 自定义Realm
////     */
////    @Bean
////    public UserRealm userRealm(EhCacheManager cacheManager)
////    {
////        UserRealm userRealm = new UserRealm();
////        userRealm.setCacheManager(cacheManager);
////        return userRealm;
////    }
//
//    /**
//     * 自定义sessionDAO会话
//     */
//    @Bean
//    public OnlineSessionDAO sessionDAO()
//    {
//        OnlineSessionDAO sessionDAO = new OnlineSessionDAO();
//        return sessionDAO;
//    }
//
//    /**
//     * 自定义sessionFactory会话
//     */
//    @Bean
//    public OnlineSessionFactory sessionFactory()
//    {
//        OnlineSessionFactory sessionFactory = new OnlineSessionFactory();
//        return sessionFactory;
//    }
//
//    /**
//     * 自定义sessionFactory调度器
//     */
//    @Bean
//    public SpringSessionValidationScheduler sessionValidationScheduler()
//    {
//        SpringSessionValidationScheduler sessionValidationScheduler = new SpringSessionValidationScheduler();
//        // 相隔多久检查一次session的有效性，单位毫秒，默认就是10分钟
//        sessionValidationScheduler.setSessionValidationInterval(validationInterval * 60 * 1000);
//        // 设置会话验证调度器进行会话验证时的会话管理器
//        sessionValidationScheduler.setSessionManager(sessionValidationManager());
//        return sessionValidationScheduler;
//    }
//
//    /**
//     * 会话管理器
//     */
//    @Bean
//    public OnlineWebSessionManager sessionValidationManager()
//    {
//        OnlineWebSessionManager manager = new OnlineWebSessionManager();
//        // 加入缓存管理器
//        manager.setCacheManager(getEhCacheManager());
//        // 删除过期的session
//        manager.setDeleteInvalidSessions(true);
//        // 设置全局session超时时间
//        manager.setGlobalSessionTimeout(expireTime * 60 * 1000);
//        // 去掉 JSESSIONID
//        manager.setSessionIdUrlRewritingEnabled(false);
//        // 是否定时检查session
//        manager.setSessionValidationSchedulerEnabled(true);
//        // 自定义SessionDao
//        manager.setSessionDAO(sessionDAO());
//        // 自定义sessionFactory
//        manager.setSessionFactory(sessionFactory());
//        return manager;
//    }
//
//    /**
//     * 会话管理器
//     */
////    @Bean
////    public OnlineWebSessionManager sessionManager()
////    {
////        OnlineWebSessionManager manager = new OnlineWebSessionManager();
////        // 加入缓存管理器
////        manager.setCacheManager(getEhCacheManager());
////        // 删除过期的session
////        manager.setDeleteInvalidSessions(true);
////        // 设置全局session超时时间
////        manager.setGlobalSessionTimeout(expireTime * 60 * 1000);
////        // 去掉 JSESSIONID
////        manager.setSessionIdUrlRewritingEnabled(false);
////        // 定义要使用的无效的Session定时调度器
////        manager.setSessionValidationScheduler(sessionValidationScheduler());
////        // 是否定时检查session
////        manager.setSessionValidationSchedulerEnabled(true);
////        // 自定义SessionDao
////        manager.setSessionDAO(sessionDAO());
////        // 自定义sessionFactory
////        manager.setSessionFactory(sessionFactory());
////        return manager;
////    }
//
//    /**
//     * 安全管理器
//     */
//    @Bean
//    public SecurityManager securityManager(MyShiroCasRealm userRealm)
//    {
//        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
//        // 设置realm.
//        securityManager.setRealm(userRealm);
//        // 记住我
//        securityManager.setRememberMeManager(rememberMeManager());
//        // 注入缓存管理器;
//        securityManager.setCacheManager(getEhCacheManager());
//        // session管理器
////        securityManager.setSessionManager(sessionManager());
//        return securityManager;
//    }
//
//    /**
//     * 退出过滤器
//     */
//    public LogoutFilter logoutFilter()
//    {
//        LogoutFilter logoutFilter = new LogoutFilter();
//        logoutFilter.setLoginUrl(loginUrl);
//        return logoutFilter;
//    }
//
//    /**
//     * Shiro过滤器配置
//     */
////    @Bean
//    public void shiroFilterFactoryBean(ShiroFilterFactoryBean shiroFilterFactoryBean,SecurityManager securityManager)
//    {
////        ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();
//        // Shiro的核心安全接口,这个属性是必须的
////        shiroFilterFactoryBean.setSecurityManager(securityManager);
//        // 身份认证失败，则跳转到登录页面的配置
////        shiroFilterFactoryBean.setLoginUrl(loginUrl);
////        // 权限认证失败，则跳转到指定页面
////        shiroFilterFactoryBean.setUnauthorizedUrl(unauthorizedUrl);
//        // Shiro连接约束配置，即过滤链的定义
//        LinkedHashMap<String, String> filterChainDefinitionMap = new LinkedHashMap<>();
//        filterChainDefinitionMap.put(casFilterUrlPattern, "casFilter");
//        // 对静态资源设置匿名访问
//        filterChainDefinitionMap.put("/favicon.ico**", "anon");
//        filterChainDefinitionMap.put("/ruoyi.png**", "anon");
//        filterChainDefinitionMap.put("/css/**", "anon");
//        filterChainDefinitionMap.put("/docs/**", "anon");
//        filterChainDefinitionMap.put("/fonts/**", "anon");
//        filterChainDefinitionMap.put("/img/**", "anon");
//        filterChainDefinitionMap.put("/ajax/**", "anon");
//        filterChainDefinitionMap.put("/js/**", "anon");
//        filterChainDefinitionMap.put("/ruoyi/**", "anon");
//        filterChainDefinitionMap.put("/druid/**", "anon");
//        filterChainDefinitionMap.put("/captcha/captchaImage**", "anon");
//        filterChainDefinitionMap.put("index","user");
////        // 退出 logout地址，shiro去清除session
////        filterChainDefinitionMap.put("/logout", "logout");
////        // 不需要拦截的访问
////        filterChainDefinitionMap.put("/login", "anon,captchaValidate");
//        // 系统权限列表
//        // filterChainDefinitionMap.putAll(SpringUtils.getBean(IMenuService.class).selectPermsAll());
////
////        Map<String, Filter> filters = new LinkedHashMap<>();
////        filters.put("onlineSession", onlineSessionFilter());
////        filters.put("syncOnlineSession", syncOnlineSessionFilter());
////        filters.put("captchaValidate", captchaValidateFilter());
////        // 注销成功，则跳转到指定页面
//////        filters.put("logout", logoutFilter());
////        shiroFilterFactoryBean.setFilters(filters);
//
//        // 所有请求需要认证authc
////        filterChainDefinitionMap.put("/**", "user,onlineSession,syncOnlineSession");
//        filterChainDefinitionMap.put("/system/**","authc,onlineSession");
//        filterChainDefinitionMap.put("/index","onlineSession,syncOnlineSession");
//        filterChainDefinitionMap.put("/**", "authc");
//        shiroFilterFactoryBean.setFilterChainDefinitionMap(filterChainDefinitionMap);
//
////        return shiroFilterFactoryBean;
//    }
//
//    /**
//     * 自定义在线用户处理过滤器
//     */
//    @Bean
//    public OnlineSessionFilter onlineSessionFilter()
//    {
//        OnlineSessionFilter onlineSessionFilter = new OnlineSessionFilter();
//        onlineSessionFilter.setLoginUrl(loginUrl);
//        return onlineSessionFilter;
//    }
//
//    /**
//     * 自定义在线用户同步过滤器
//     */
//    @Bean
//    public SyncOnlineSessionFilter syncOnlineSessionFilter()
//    {
//        SyncOnlineSessionFilter syncOnlineSessionFilter = new SyncOnlineSessionFilter();
//        return syncOnlineSessionFilter;
//    }
//
//    /**
//     * 自定义验证码过滤器
//     */
//    @Bean
//    public CaptchaValidateFilter captchaValidateFilter()
//    {
//        CaptchaValidateFilter captchaValidateFilter = new CaptchaValidateFilter();
//        captchaValidateFilter.setCaptchaEbabled(captchaEbabled);
//        captchaValidateFilter.setCaptchaType(captchaType);
//        return captchaValidateFilter;
//    }
//
//    /**
//     * cookie 属性设置
//     */
//    public SimpleCookie rememberMeCookie()
//    {
//        SimpleCookie cookie = new SimpleCookie("rememberMe");
//        cookie.setDomain(domain);
//        cookie.setPath(path);
//        cookie.setHttpOnly(httpOnly);
//        cookie.setMaxAge(maxAge * 24 * 60 * 60);
//        return cookie;
//    }
//
//    /**
//     * 记住我
//     */
//    public CookieRememberMeManager rememberMeManager()
//    {
//        CookieRememberMeManager cookieRememberMeManager = new CookieRememberMeManager();
//        cookieRememberMeManager.setCookie(rememberMeCookie());
//        cookieRememberMeManager.setCipherKey(Base64.decode("fCq+/xW488hMTCD+cmJ3aQ=="));
//        return cookieRememberMeManager;
//    }
//
//    /**
//     * thymeleaf模板引擎和shiro框架的整合
//     */
//    @Bean
//    public ShiroDialect shiroDialect()
//    {
//        return new ShiroDialect();
//    }
//
//    /**
//     * 开启Shiro注解通知器
//     */
//    @Bean
//    public AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor(
//            @Qualifier("securityManager") SecurityManager securityManager)
//    {
//        AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor = new AuthorizationAttributeSourceAdvisor();
//        authorizationAttributeSourceAdvisor.setSecurityManager(securityManager);
//        return authorizationAttributeSourceAdvisor;
//    }
//
//
//
//
//
//    // cas server地址
//    public static final String casServerUrlPrefix = "http://localhost:8080/cas";
//    // Cas登录页面地址
//    public static final String casLoginUrl = casServerUrlPrefix + "/login";
//    // Cas登出页面地址
//    public static final String casLogoutUrl = casServerUrlPrefix + "/logout";
//    // 当前工程对外提供的服务地址
//    public static final String shiroServerUrlPrefix = "http://localhost:10001";
//    // casFilter UrlPattern
//    public static final String casFilterUrlPattern = "/cas";
//    // 登录地址
//    public static final String TloginUrl = casLoginUrl + "?service=" + shiroServerUrlPrefix + casFilterUrlPattern;
//    // 登出地址
//    public static final String logoutUrl = casLogoutUrl+"?service="+shiroServerUrlPrefix;
//    // 登录成功地址
//    public static final String loginSuccessUrl = "/index";
//    // 权限认证失败跳转地址
//    public static final String TunauthorizedUrl = "/error/403.html";
//
//    @Bean(name = "myShiroCasRealm")
//    public MyShiroCasRealm myShiroCasRealm(EhCacheManager cacheManager) {
//        MyShiroCasRealm realm = new MyShiroCasRealm();
//        realm.setCacheManager(cacheManager);
//        //realm.setCasServerUrlPrefix(ShiroCasConfiguration.casServerUrlPrefix);
//        // 客户端回调地址
//        //realm.setCasService(ShiroCasConfiguration.shiroServerUrlPrefix + ShiroCasConfiguration.casFilterUrlPattern);
//        return realm;
//    }
//
//    /**
//     * 注册单点登出listener
//     * @return
//     */
//    @Bean
//    public ServletListenerRegistrationBean singleSignOutHttpSessionListener(){
//        ServletListenerRegistrationBean bean = new ServletListenerRegistrationBean();
//        bean.setListener(new SingleSignOutHttpSessionListener());
////        bean.setName(""); //默认为bean name
//        bean.setEnabled(true);
//        //bean.setOrder(Ordered.HIGHEST_PRECEDENCE); //设置优先级
//        return bean;
//    }
//
//    /**
//     * 注册单点登出filter
//     * @return
//     */
//    @Bean
//    public FilterRegistrationBean singleSignOutFilter(){
//        FilterRegistrationBean bean = new FilterRegistrationBean();
//        bean.setName("singleSignOutFilter");
//        bean.setFilter(new SingleSignOutFilter());
//        bean.addUrlPatterns("/*");
//        bean.setEnabled(true);
//        //bean.setOrder(Ordered.HIGHEST_PRECEDENCE);
//        return bean;
//    }
//
//
//
//    /**
//     * 注册DelegatingFilterProxy（Shiro）
//     *
//     * @return
//     * @author SHANHY
//     * @create  2016年1月13日
//     */
//    @Bean
//    public FilterRegistrationBean delegatingFilterProxy() {
//        FilterRegistrationBean filterRegistration = new FilterRegistrationBean();
//        filterRegistration.setFilter(new DelegatingFilterProxy("shiroFilter"));
//        //  该值缺省为false,表示生命周期由SpringApplicationContext管理,设置为true则表示由ServletContainer管理
//        filterRegistration.addInitParameter("targetFilterLifecycle", "true");
//        filterRegistration.setEnabled(true);
//        filterRegistration.addUrlPatterns("/*");
//        return filterRegistration;
//    }
//
//
////    @Bean(name = "lifecycleBeanPostProcessor")
////    public LifecycleBeanPostProcessor getLifecycleBeanPostProcessor() {
////        return new LifecycleBeanPostProcessor();
////    }
//
//
//    /**
//     * CAS过滤器
//     *
//     * @return
//     * @author SHANHY
//     * @create  2016年1月17日
//     */
//    @Bean(name = "casFilter")
//    public CasFilter getCasFilter() {
//        CasFilter casFilter = new CasFilter();
//        casFilter.setName("casFilter");
//        casFilter.setEnabled(true);
//        // 登录失败后跳转的URL，也就是 Shiro 执行 CasRealm 的 doGetAuthenticationInfo 方法向CasServer验证tiket
//        casFilter.setFailureUrl(loginSuccessUrl);// 我们选择认证失败后再打开登录页面
//        return casFilter;
//    }
//
//    /**
//     * ShiroFilter<br/>
//     * 注意这里参数中的 StudentService 和 IScoreDao 只是一个例子，因为我们在这里可以用这样的方式获取到相关访问数据库的对象，
//     * 然后读取数据库相关配置，配置到 shiroFilterFactoryBean 的访问规则中。实际项目中，请使用自己的Service来处理业务逻辑。
//     *
//     * @param securityManager
//     * @param casFilter
//     * @return
//     * @author SHANHY
//     * @create  2016年1月14日
//     */
//    @Bean(name = "shiroFilter")
//    public ShiroFilterFactoryBean getShiroFilterFactoryBean(SecurityManager securityManager, CasFilter casFilter) {
//        ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();
//        // 必须设置 SecurityManager
//        shiroFilterFactoryBean.setSecurityManager(securityManager);
//        // 如果不设置默认会自动寻找Web工程根目录下的"/login.jsp"页面
//        shiroFilterFactoryBean.setLoginUrl(TloginUrl);
//        // 登录成功后要跳转的连接
//        shiroFilterFactoryBean.setSuccessUrl(loginSuccessUrl);
//        shiroFilterFactoryBean.setUnauthorizedUrl(TunauthorizedUrl);
//        // 添加casFilter到shiroFilter中
//        Map<String, Filter> filters = new HashMap<>();
//        filters.put("casFilter", casFilter);
//        filters.put("onlineSession", onlineSessionFilter());
//        filters.put("syncOnlineSession", syncOnlineSessionFilter());
////        filters.put("captchaValidate", captchaValidateFilter());
//         filters.put("logout",logoutFilter());
//        shiroFilterFactoryBean.setFilters(filters);
//
//        shiroFilterFactoryBean(shiroFilterFactoryBean, securityManager);
//        return shiroFilterFactoryBean;
//    }
//
//
//}
