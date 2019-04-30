# 第六章 Spring Boot SSO
一个企业级的应用系统可能存在很多应用系统，每个应用系统都需要设计安全管理，及  
实现用户的认证和访问授权，但是不可能为每一个应用系统都设计一套安全管理，这样  
不但耗时耗力，而且要做重复的工作，也不适宜建立统一的用户中心。这就需要使用单  
点登录（Single Sign On，SSO）的方式来建立一个登录认证系统，并且实现对用户的  
统一管理。对于一个开放平台来说，SSO 也能为合作伙伴提供用户的身份认证和授权管  
理。

将使用第 5 章的安全设计，再略加以扩展来建立一个 SSO 管理系统。这里介绍的 SSO  
管理系统，是在使用 Spring Security 安全管理的基础上，再结合 OAuth2 认证授权  
协议来实现的，它不但适用于大型的分布式管理系统，也适用于为第三方提供统一的用  
户管理和认证的平台。

## 6.1 模块化设计
本章的实例工程由于涉及的功能较多，将按照表 6-1，对实例工程实行模块化管理。其  
中，每个模块都是一个独立的项目，数据库管理模块为其他模块提供数据管理支持，安  
全配置模块为客户端提供安全配置和授权管理支持，登录认证模块提供单点登录认证  
（即 SSO）功能，共享资源模块为客户端提供登录用户需要的一些共享资源，两个客户  
端应用是使用 SSO 系统的两个实例。

表 6-1 实例工程模块列表

| 项目 | 工程 | 类型 | 功能 |  
| :-: | :-: | :-: | :-: |  
| 数据库管理模块 | mysql | 程序集成 | 数据库管理 |  
| 安全配置模块 | security | 程序集成 | 安全策略配置和权限管理 |  
| 登录认证模块 | login | Web 应用 | SSO 登录认证（使用端口：80）|  
| 共享资源模块 | resource | Web 应用 | 共享资源（使用端口：8083）|  
| 客户端应用 1 | web1 | Web 应用 | 客户端 1（使用端口：8081）|  
| 客户端应用 2 | web2 | Web 应用 | 客户端 2（使用端口：8082）|  

使用模块化设计可以提高代码的复用性，避免重复开发，从而提高开发速度和工作效率。  
例如，实例工程的数据库管理模块和安全配置模块能够被其他模块公用，从而减少了大  
部分重复的工作。

其中数据库管理模块 mysql 与第 5 章的 mysql 模块的功能完全相同，它为其他各个  
模块提供了数据库管理功能，同样具有部门、用户和角色三个实体，并且提供了对这三  
个实体对象的增删改查等操作的功能。

## 6.2 登录认证模块
如果只是本地的登录认证，只要使用 Spring Security 就足够了。由于使用 SSO 实现  
了远程的登录认证功能，所以在登录认证系统中，需要增加 OAuth2 协议，让它可以支  
持第三方应用的认证和授权。

登录认证系统将建立一个用户中心，对使用 SSO 服务的每一个应用系统，提供统一的  
用户管理。而对于一个用户来说，使用任何一个应用系统，都可以通过 SSO 的 OAuth  
协议进行认证和授权确认

### 6.2.1 使用 OAuth2
要使用 OAuth2，在登录认证模块和安全配置模块中都要在工程的 Maven 依赖管理中  
增加 OAuth2 的依赖配置，如代码清单 6-1 所示

代码清单 6-1 
```
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-starter-oauth2</artifactId>
</dependency>
```
### 6.2.2 创建数字证书
在 OAuth2 的认证服务端中，需要一个数字证书，为通信中的数字签名等功能提供支持。  
这个数字证书可以使用 Java 的 keystore 来生成。

在 Windows 操作系统中打开一个命令窗口，使用下列的指令可以生成一个数字证书
```
C:\Users\jaunt>keytool -genkey -keystore keystore.jks -alias tycoonclient -keyalg RSA
输入密钥库口令:
再次输入新口令:
您的名字与姓氏是什么?
  [Unknown]:  localhost
您的组织单位名称是什么?
  [Unknown]:  test
您的组织名称是什么?
  [Unknown]:  test
您所在的城市或区域名称是什么?
  [Unknown]:  gz
您所在的省/市/自治区名称是什么?
  [Unknown]:  gd
该单位的双字母国家/地区代码是什么?
  [Unknown]:  cn
CN=localhost, OU=test, O=test, L=gz, ST=gd, C=cn是否正确?
  [否]:  y

输入 <tycoonclient> 的密钥口令
        (如果和密钥库口令相同, 按回车):

Warning:
JKS 密钥库使用专用格式。建议使用 "keytool -importkeystore -srckeystore keystore.jks -destkeystore keystore.jks -deststoretype pkcs12" 迁移到行业标准格式 PKCS12。
```
在上面的操作过程中，输入的密码是 tc123456，证书的别名设定为 tycoonclient，  
证书的文件保存为 keystore.jks。

然后将生成的证书文件拷贝到登录认证模块的 resources 文件夹中，并在 OAuth2  
配置中设定其相应的参数。

### 6.2.3 认证服务端配置
登录认证模块实现了 SSO 认证和授权服务的功能，在这里必须对 OAuth2 的认证  
和授权服务，以及对 Spring Security 的安全管理策略等进行一些相关的设计和  
配置，为使用 SSO 的客户端提供认证和授权的管理功能。

#### 6.2.3.1 OAuth2 服务端配置
在登录认证模块中，编写一个 OAuthConfigurer 配置类程序，如代码清单 6-2 所示，  
它继承了 AuthorizationServerConfigurerAdapter。其中，使用注解  
@EnableAuthorizationServer 来启用 OAuth2 的认证服务器功能。在 jwtAccessTokenConverter
方法中使用上面生成的数字证书：keystore.jks，并设置了密码和别名等参数。  
在重载的 configure 方法中设定 OAuth2 的客户端 ID 为 ssoclient，密钥为 ssosecret，
这将在使用 SSO 的客户端的配置中用到。另外，注意“autoApprove(true)”这行  
代码设定了自动确认授权，这样登录用户登录后，不再需要进行一次授权确认操作。

代码清单 6-2 OAuth2 服务端配置
```
@Configuration
@EnableAuthorizationServer
public class OAuthConfigurer extends AuthorizationServerConfigurerAdapter {

    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        KeyPair keyPair = new KeyStoreKeyFactory(new ClassPathResource(
                "keystore.jks"), "tc123456".toCharArray()).getKeyPair("tycoonclient");
        converter.setKeyPair(keyPair);
        return converter;
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients)
            throws Exception {
        clients.inMemory().withClient("ssoclient").secret("ssosecret")
                .autoApprove(true) //自动确认授权，用户登录后，不再需要进行一次授权确认操作。
                .authorizedGrantTypes("authorization_code", "refresh_token").scopes("openid");
    }
    ……
}
```

#### 6.2.3.2 Spring Security 服务端配置
因为认证服务器的 Spring Security 安全策略与客户端的安全策略配置不同，所以  
它没有使用工程中安全配置模块中的配置，而是单独使用一个配置类来实现，如代  
码清单 6-3 所示。这里有点像第 5 章的安全策略配置，依然提供了记住用户登录状  
态的功能，这样当用户选择记住登录状态登录后，只要用户不执行退出，在记住登  
录状态的有效期内，重新打开授权的链接时就可以不用再次登录。登录页面设定还  
是使用“/login”。但是这里没有针对角色的一些权限管理配置，这是因为在登录  
认证模块中只提供了登录认证功能，并不提供其他访问链接，所以这里不需要配置  
一些链接的角色权限管理。

代码清单 6-3 认证服务器的安全策略配置
```
@Configuration
@Order(SecurityProperties.ACCESS_OVERRIDE_ORDER)
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
    @Autowired
    private CustomUserDetailsService customUserDetailsService;
    @Autowired @Qualifier("dataSource")
    private DataSource dataSource;

    @Override
    protected void configure(AuthenticationManagerBuilder auth)
            throws Exception {
        auth.userDetailsService(customUserDetailsService).passwordEncoder(passwordEncoder());
        //remember me
        auth.eraseCredentials(false);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.formLogin().loginPage("/login").permitAll().successHandler(loginSuccessHandler())
                .and().authorizeRequests()
                .antMatchers("/images/**", "/checkcode", "/scripts/**", "/styles/**").permitAll()
                .anyRequest().authenticated()
                .and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.NEVER)
                .and().exceptionHandling().accessDeniedPage("/deny")
                .and().rememberMe().tokenValiditySeconds(86400).tokenRepository(tokenRepository());
    }
    ……
}
```

## 6.3 安全配置模块
安全配置模块集成了 SSO 客户端的安全策略配置和权限管理功能，可以供使用 SSO 的  
客户端使用。代码清单 6-4 是客户端的安全策略配置，其中，注解 @EnableOAuth2Sso  
将应用标注为一个 SSO 客户端，重载的 configure 方法使用了 HttpSecurity 来配置  
一些安全管理策略。注意这里没有登录链接的配置，因为登录认证的功能已经交给 OAuth2  
处理了。另外，CustomFilterSecurityInterceptor 设定了使用自定义的权限管理过滤器，  
这个功能还是与第 5 章的设计一样，这里不再赘述。 

代码清单 6-4 客户端安全策略配置
``` 
@Configuration
@EnableOAuth2Sso
@EnableConfigurationProperties(SecuritySettings.class)
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private SecuritySettings settings;

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http
                .antMatcher("/**").authorizeRequests()
                .antMatchers(settings.getPermitall().split(",")).permitAll()
                .anyRequest().authenticated()
                .and().csrf().requireCsrfProtectionMatcher(csrfSecurityRequestMatcher())
                .csrfTokenRepository(csrfTokenRepository()).and()
                .addFilterAfter(csrfHeaderFilter(), CsrfFilter.class)
                .logout().logoutUrl("/logout").permitAll()
                .logoutSuccessUrl(settings.getLogoutsuccssurl())
                .and()
                .exceptionHandling().accessDeniedPage(settings.getDeniedpage());
    }


    @Bean
    public CustomFilterSecurityInterceptor customFilter() throws Exception{
        CustomFilterSecurityInterceptor customFilter = new CustomFilterSecurityInterceptor();
        customFilter.setSecurityMetadataSource(securityMetadataSource());
        customFilter.setAccessDecisionManager(accessDecisionManager());
        customFilter.setAuthenticationManager(authenticationManager);
        return customFilter;
    }
    ……
}
```

## 6.4 SSO 客户端
SSO 客户端要使用安全配置模块的功能，需要在工程的 Maven 依赖管理中，增加一个依  
赖配置，如代码清单 6-5 所示。

代码清单 6-5 引用安全配置模块的依赖配置
``` 
<dependency>
    <groupId>springboot.demo</groupId>
    <artifactId>security</artifactId>
    <version>${project.version}</version>
</dependency>
```
### 6.4.1 客户端配置
当客户端引用安全配置模块之后，就必须在配置文件 application.yml 中进行一些相关  
配置，才能正常使用。代码清单 6-6 是一个 SSO 客户端的配置，它包含两方便的内容，  
其中 security 是 OAuth2 的配置，securityconfig 是 Spring Security 的配置。

在 OAuth2 的配置中，loginPath 是一个登录的链接地址，clientId 和 clientSecret  
是由 SSO 认证服务器提供的客户端 ID 和密钥，accessTokenUri 是取得令牌的链接地  
址，userAuthorizationUri 是用户授权确认的链接地址，keyUri 是当客户端被指定为  
资源服务器时所用的令牌链接地址。

Spring Security 的配置中是设计的一些自定义配置参数，它将被安全管理策略配置类  
调用，其中 logoutsuccessurl 是一个登出成功的链接地址，其他配置参数与第 5 章的  
安全配置基本相同。

代码清单 6-6 SSO 客户端配置
``` 
security:
  ignored: /favicon.ico,/scripts/**,/styles/**,/images/**
  sessions: ALWAYS
  oauth2:
      sso:
        loginPath: /login
      client:
        clientId: ssoclient
        clientSecret: ssosecret
        accessTokenUri: http://localhost/oauth/token
        userAuthorizationUri: http://localhost/oauth/authorize
        clientAuthenticationScheme: form
      resource:
        jwt:
          keyUri: http://localhost/oauth/token_key

securityconfig:
  logoutsuccssurl: /tosignout
  permitall: /rest/**,/bb**
  deniedpage: /deny
  urlroles: /**/new/** = admin;
            /**/edit/** = admin,editor;
            /**/delete/** = admin
```

### 6.4.2 登录登出设计
登录登出的设计，虽然在 Spring Security 中已经实现，但是对于使用 SSO 的客户端  
来说，必须进行一些合理的调整，否则如果设计不当，就有可能出现无法正常退出或者  
登录失败的情况。

代码清单 6-7 是客户端的一个登出设计，使用一个重定向链接 "redirect:/#/"  来刷  
新当前访问页面，从而触发系统检查用户的授权状态，如果用户未被授权，则引导用户  
到登录认证服务器中登录。

代码清单 6-7 客户端登录控制器
```
    @RequestMapping("/login")
    public String login() {
        return "redirect:/#/";
    }
```

代码清单 6-8 是客户端的一个登出设计，退出时首先通过用户确认，然后使用 POST  
方式执行表单 logoutform 的退出提交请求，这个请求已由 Spring Security 实现，  
执行一些清除会话和登录状态等操作，并将当前操作界面重定向到登出成功页面上。

这里需要注意的是，用户这时只是退出当前客户端而已，并没有在 SSO 服务端中执  
行过退出请求，也就是说，在 SSO 认证服务端中，还保存着用户的登录状态。如果  
这时返回原来的客户端，或者访问其他由授权的客户端，都不会要求用户登录并能  
正常访问。为了能真正的退出，还必须在 SSO 服务端中再执行一次退出请求。这个  
退出请求必须由程序来处理，而不能要求用户转到 SSO 服务端中再执行一次退出。

代码清单 6-8 客户端登出设计
```$xslt
<a href="javascript:void(0)" id="logout">[退出]</a>
……
<form th:action="@{/logout}" method="post" id="logoutform">
</form>
<div class="footBox" th:replace="fragments/footer :: footer"></div>
<script type="text/javascript">
    $(function () {
        $("#logout").click(function () {
            if (confirm('您确定退出吗？')) {
                $("#logoutform").submit();
            }
        });
    });
</script>
```

在客户端配置中有一个成功退出的链接地址，当用户在客户端中成功退出时，将被  
重定向到这个链接地址。代码清单 6-9 是这个链接的页面设计，它只做一件简单的  
事情，即在当前页面中做一个跳转链接，转到 SSO 服务端中执行退出请求。

代码清单 6-9 跳转到 SSO 服务端中执行登出
```
<script>
    function to_sso(){
        location.href = "http://localhost/signout";
    }
</script>
<body onload="to_sso()">
</body>
```

代码清单 6-10 是 SSO 服务端的登出控制器设计，只有请求这个链接，才能让用户  
完全退出当前的登录状态。程序中使用 request.logout() 来请求 Spring Security  
执行退出请求，然后返回 SSO 的登录界面，以刷新当前的页面状态。

代码清单 6-10 SSO 服务端登出控制器
```
@RequestMapping("/signout")
    public String signout(HttpServletRequest request) throws Exception{
        request.logout();
        return "tologin";
    }
```

代码清单 6-11 是接收上面的请求后，返回的一个页面设计，它同样也只做一件简单  
的事情，即将当前页面跳转到用户登录界面上。

代码清单 6-11 跳转到登录界面
```
<script>
    <!--
    function new_window(){
        location.href = "/login";
    }
    //-->
</script>
<body onload="new_window()">
</body>
```

这样，用户不管在哪个客户端中执行退出，通过上面的跳转，最终都将被引导到 SSO   
服务端的登录界面上。通过这些流程的处理，用户的一个退出请求才能彻底退出登录  
状态。当然，上面这些跳转对于用户来说，是完全透明的。

用户打开任何一个客户端的页面进行登录，登录成功后将被引导到最初打开的页面上。  
如果用户直接在 SSO 认证服务端上登录，必须有一个成功登录后的默认主页，这个  
页面可以配置一些其他客户端的导航链接。因为把登录成功的默认主页设计放置在  
客户端 1 的主页上，所以如果用户从 SSO 服务器中直接登录，就可以在 SSO 服务  
器的主页上做一个跳转，如代码清单 6-12 所示，将跳转到客户端 1 的主页上。

代码清单 6-12 登录成功的默认链接设计
```
<script>
    <!--
    function new_window(){
        location.href = "http://localhost:8081/";
    }
    //-->
</script>

<!-- onload="new_window()"-->
<body onload="new_window()">
......请稍候

</body>
```

##  6.5共享资源服务
实例工程的共享资源模块，可以为已经授权的用户提供一些共享信息服务。代码清  
单 6-13 是共享资源模块的主程序，它使用 @EnableResourceServer 标注这个应用  
是一个资源服务器。

代码清单 6-13 资源服务器主程序
``` 
@SpringBootApplication
@EnableResourceServer
@ComponentScan(basePackages = "com.test")
public class ResourceApplication {
    public static void main(String[] args) {
        SpringApplication.run(ResourceApplication.class, args);
    }
}
```

一个应用被标注为资源服务器后，在浏览器中就不能直接访问，如果在浏览器上打开  
这样的客户端，将只能看到如下所示信息提示：
``` 
This XML file does not appear to have any style information associated with it. The document tree is shown below.
<oauth>
<error_description>
Full authentication is required to access this resource
</error_description>
<error>unauthorized</error>
</oauth>
```

### 6.5.1 提供共享资源接口
启用资源服务器功能之后，就能够对外提供资源信息服务。代码清单 6-14 是一个共  
享登录用户信息的接口设计，这是提供了一个“/user”链接的控制器，程序中通过  
Principal 取得登录用户的用户名，然后通过用户名在数据库中查出用户的详细信息，  
最后返回包含用户信息的一个 Map 对象。

代码清单 6-14 共享用户信息接口设计
``` 
@RestController
public class UserController {
    @Autowired
    private UserRepository userRepository;

    @RequestMapping("/user")
    public Map<String, Object> user(Principal puser) {
        User user = userRepository.findByName(puser.getName());
        Map<String, Object> userinfo = new HashMap<>();
        userinfo.put("id", user.getId());
        userinfo.put("name",user.getName());
        userinfo.put("email", user.getEmail());
        userinfo.put("department",user.getDepartment().getName());
        userinfo.put("createdate", user.getCreatedate());
        return userinfo;
    }
}
```

### 6.5.2 使用共享资源
在客户端中要使用资源服务器的共享信息，可以使用 spring-cloud-zuul 提供的一个  
路由服务来实现。代码清单 6-15 是客户端应用 2 的主程序，它使用注解 @EnableZuulProxy  
来启用 Zuul 路由代理服务。

代码清单 6-15 客户端应用 2 的主程序
``` 
@SpringBootApplication
@EnableZuulProxy
@ComponentScan(basePackages = "com.test")
public class Web2Application {
    public static void main(String[] args) {
        SpringApplication.run(Web2Application.class, args);
    }
}
```

在工程配置文件 application.yml 中使用如代码清单 6-16 所示的配置，配置一个路由  
资源，其中 path 设定资源的访问路径，url 指定路由的服务方。

代码清单 6-16 使用资源服务的路由配置
``` 
zuul:
  routes:
    resource:
      path: /resource/**
      url: http://localhost:8083
      stripPrefix: true
      retryable:
```
这样就可以在客户端应用 2 中使用如下的链接进行访问：  
http://localhost:8082/resource/user  
或者通过程序使用如下的 Ajax 方式获得数据(web2:/static/scripts/user/index.js)：  
``` 
$.get('./resource/user',{ts:new Date().getTime()},function(data)
```

###  6.5.3 查询登录用户的详细信息
在单独使用 Spring Security 安全管理的应用中，只要在控制器中使用 Principal,  
就能取得用户的完整信息，或者使用如代码清单 6-17 所示的代码，也能很容易地获取  
登录用户的详细信息。但是，使用 SSO 之后，这种方法就不能适用了，这时如果使  
用 getDetails() 将返回一个空值，而在控制器中使用 Principal 也只能返回登录  
用户的用户名、用户拥有的角色和登录令牌等信息而已，用户的其他信息如性别、  
邮箱等将不能取得。这是 OAuth2 基于安全的考虑而设计的，因为 SSO 涉及了第三  
方的应用请求，所以它保护了登录用户的隐私信息。

代码清单 6-17 
```
Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
User user = (User)authentication.getDetails();
```

如果需要取得登录用户的详细信息，如性别、邮箱、所属的部门等，就只能像前面  
提到的那样，使用资源服务器提供的共享资源接口，然后通过 Zuul 路由代理服务  
获取已经登录的用户详细信息。
代码清单 6-18 是一个使用 Ajax 获取登录用户的详细信息的例子

代码清单 6-18 从资源服务器中获取登录用户的详细信息
```
function getuserinfo(){
    $.get('./resource/user',{ts:new Date().getTime()},function(data){
        user = data;
        var $list = $('#tbodyContent').empty();
            var html = "" ;
            html += '<tr> ' +
                '<td>'+ (data.id==null?'':data.id) +'</td>' +
                '<td>'+ (data.name==null?'':data.name) +'</td>' +
                '<td>'+ (data.email==null?'':data.email) +'</td>' +
                '<td>'+ (data.department==null?'' :data.department) +'</td>' +
                '<td>'+ (data.createdate==null?'': getSmpFormatDateByLong(data.createdate,true)) +'</td>';
            html +='</tr>' ;

            $list.append($(html));
    });
}
```