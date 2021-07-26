package com.jacknie.test.config

import com.jacknie.test.config.oauth2.ReactiveClientAuthenticationManager
import com.jacknie.test.config.social.*
import com.jacknie.test.handler.AuthorizationHandler
import com.jacknie.test.handler.IndexHandler
import com.jacknie.test.handler.SignupHandler
import com.jacknie.test.handler.TokenHandler
import com.jacknie.test.model.MemberSocialType
import com.jacknie.test.model.MemberSocialType.*
import com.nimbusds.jose.jwk.RSAKey
import java.security.KeyFactory
import java.security.KeyStore
import java.security.interfaces.RSAPrivateCrtKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.RSAPublicKeySpec
import org.springframework.context.support.BeanDefinitionDsl
import org.springframework.context.support.beans
import org.springframework.core.env.Environment
import org.springframework.core.env.get
import org.springframework.core.io.ClassPathResource
import org.springframework.http.HttpHeaders
import org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED
import org.springframework.http.MediaType.TEXT_HTML
import org.springframework.r2dbc.connection.init.ConnectionFactoryInitializer
import org.springframework.r2dbc.connection.init.ResourceDatabasePopulator
import org.springframework.security.authentication.DelegatingReactiveAuthenticationManager
import org.springframework.security.authentication.ReactiveAuthenticationManager
import org.springframework.security.authentication.UserDetailsRepositoryReactiveAuthenticationManager
import org.springframework.security.config.web.server.SecurityWebFiltersOrder
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.crypto.factory.PasswordEncoderFactories
import org.springframework.security.oauth2.client.authentication.OAuth2LoginReactiveAuthenticationManager
import org.springframework.security.oauth2.client.endpoint.WebClientReactiveAuthorizationCodeTokenResponseClient
import org.springframework.security.oauth2.client.oidc.authentication.OidcAuthorizationCodeReactiveAuthenticationManager
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository
import org.springframework.security.oauth2.core.AuthenticationMethod
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.security.web.server.authentication.AuthenticationWebFilter
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationEntryPoint
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationFailureHandler
import org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository
import org.springframework.security.web.server.util.matcher.OrServerWebExchangeMatcher
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher
import org.springframework.web.reactive.function.server.router
import org.springframework.web.server.WebFilter

fun beans() = beans {

    //* R2DBC
    bean {
        ConnectionFactoryInitializer().apply {
            setConnectionFactory(ref())
            setDatabasePopulator(
                ResourceDatabasePopulator(
                    ClassPathResource("schema.sql"),
                    ClassPathResource("sample-data.sql")
                )
            )
        }
    }
    // */

    //* Router
    bean {
        val indexHandler = ref<IndexHandler>()
        val signupHandler = ref<SignupHandler>()
        val authHandler = ref<AuthorizationHandler>()
        val tokenHandler = ref<TokenHandler>()
        router {
            accept(TEXT_HTML).nest {
                GET("/auth", indexHandler::getIndex)
                GET("/signup", signupHandler::getSignupForm)
                POST("/signup", signupHandler::postSignupProcess)
            }
            "/oauth2".nest {
                GET("/authorize", queryParam("response_type", "code"::equals), authHandler::getAuthorizationCode)
                POST("/token", accept(APPLICATION_FORM_URLENCODED), tokenHandler::postToken)
            }
        }
    }
    // */

    //* Security
    bean { reactiveClientRegistrationRepository() }
    bean { ReactiveUserDetailsServiceImpl(ref()) }
    bean { PasswordEncoderFactories.createDelegatingPasswordEncoder() }
    bean { SocialUnregisteredUserRepository() }
    bean { WebSessionServerSecurityContextRepository() }
    bean { oauth2SecurityWebFilterChain() }
    bean { loginSecurityWebFilterChain() }
    bean { tokenSecurityWebFilterChain() }
    bean {
        val resource = ClassPathResource("keystore.p12")
        val keyStore = KeyStore.getInstance("jks")
        keyStore.load(resource.inputStream, "1234567890".toCharArray())
        val privateKey = keyStore.getKey("webflux-oauth2-sample", "1234567890".toCharArray()) as RSAPrivateCrtKey
        val spec = RSAPublicKeySpec(privateKey.modulus, privateKey.publicExponent)
        val publicKey = KeyFactory.getInstance("RSA").generatePublic(spec) as RSAPublicKey
        RSAKey.Builder(publicKey)
            .privateKey(privateKey)
            .keyStore(keyStore)
            .keyID("webflux-oauth2-sample")
            .build()
    }
    // */
}

fun BeanDefinitionDsl.BeanSupplierContext.reactiveClientRegistrationRepository(): ReactiveClientRegistrationRepository {
    val environment = ref<Environment>()
    val builders = clientRegistrationBuilders()
    @Suppress("UNCHECKED_CAST")
    val clients = MemberSocialType.values().map {
        val envNamePrefix = "spring.security.oauth2.client.registration.${it.clientRegistrationId}"
        val clientId = environment["${envNamePrefix}.client-id"]
        val clientSecret = environment["${envNamePrefix}.client-secret"]
        builders[it]!!.invoke().clientId(clientId).clientSecret(clientSecret).build()
    }
    return InMemoryReactiveClientRegistrationRepository(clients)
}

fun BeanDefinitionDsl.BeanSupplierContext.oauth2SecurityWebFilterChain(): SecurityWebFilterChain {
    return ref<ServerHttpSecurity>()
        .csrf().disable()
        .logout().disable()
        .securityContextRepository(ref())
        .securityMatcher(PathPatternParserServerWebExchangeMatcher("/oauth2/authorize"))
        .authorizeExchange { it.anyExchange().authenticated() }
        .exceptionHandling {
            it.authenticationEntryPoint(RedirectServerAuthenticationEntryPoint("/login"))
        }
        .build()
}

fun BeanDefinitionDsl.BeanSupplierContext.tokenSecurityWebFilterChain(): SecurityWebFilterChain {
    return ref<ServerHttpSecurity>()
        .csrf().disable()
        .logout().disable()
        .httpBasic().authenticationManager(ReactiveClientAuthenticationManager(ref(), ref())).and()
        .securityMatcher(PathPatternParserServerWebExchangeMatcher("/oauth2/token"))
        .authorizeExchange { it.anyExchange().authenticated() }
        .build()
}

fun BeanDefinitionDsl.BeanSupplierContext.loginSecurityWebFilterChain(): SecurityWebFilterChain {
    return ref<ServerHttpSecurity>()
        .securityContextRepository(ref())
        .securityMatcher(
            OrServerWebExchangeMatcher(
                PathPatternParserServerWebExchangeMatcher("/login/**"),
                PathPatternParserServerWebExchangeMatcher("/oauth2/authorization/**"),
                PathPatternParserServerWebExchangeMatcher("/signup/**"),
            )
        )
        .oauth2Login()
            .authenticationManager(oauth2AuthenticationManager())
            .authenticationFailureHandler(
                SocialServerAuthenticationFailureHandler("/login?error", "/signup", ref())
            )
            .and()
        .formLogin().and()
        .addFilterBefore(socialAuthenticationWebFilter(), SecurityWebFiltersOrder.FORM_LOGIN)
        .build()
}

fun BeanDefinitionDsl.BeanSupplierContext.socialAuthenticationWebFilter(): WebFilter {
    val userDetailsService = SocialReactiveUserDetailsService(ref(), ref())
    val authenticationManager = UserDetailsRepositoryReactiveAuthenticationManager(userDetailsService).apply {
        setPasswordEncoder(ref())
        setUserDetailsPasswordService(userDetailsService)
    }
    return AuthenticationWebFilter(authenticationManager).apply {
        val environment = ref<Environment>()
        val socialIdVarName = environment.getProperty("app.login.social-id.name")
        val loginSocialPattern = environment.getProperty("app.login.social.pattern")
        val exchangeMatcher = PathPatternParserServerWebExchangeMatcher(loginSocialPattern)
        val authenticationConverter = SocialServerAuthenticationConverter(ref(), exchangeMatcher) { it.variables[socialIdVarName] as String }
        setRequiresAuthenticationMatcher(exchangeMatcher)
        setAuthenticationFailureHandler(RedirectServerAuthenticationFailureHandler("/login?error"))
        setServerAuthenticationConverter(authenticationConverter)
        setAuthenticationSuccessHandler(SocialServerAuthenticationSuccessHandler(ref()))
        setSecurityContextRepository(ref())
    }
}

fun BeanDefinitionDsl.BeanSupplierContext.oauth2AuthenticationManager(): ReactiveAuthenticationManager {
    val client = WebClientReactiveAuthorizationCodeTokenResponseClient()
    @Suppress("UNCHECKED_CAST")
    val naverUserService = SocialReactiveOAuth2UserService().apply {
        userAttributeAccessSpec = { it["response"] as Map<String, Any> }
    }
    val githubUserService = SocialReactiveOAuth2UserService().apply {
        accessTokenHeaderSpec = { token, headers -> headers[HttpHeaders.AUTHORIZATION] = "token $token" }
    }
    val userServices = mapOf(
        NAVER.clientRegistrationId to naverUserService,
        GITHUB.clientRegistrationId to githubUserService,
    )
    val login = OAuth2LoginReactiveAuthenticationManager(
        client,
        SocialDelegatingReactiveOAuth2UserService(ref(), userServices),
    )
    val oidc = OidcAuthorizationCodeReactiveAuthenticationManager(
        client,
        SocialReactiveOidcUserService(ref()),
    )
    return DelegatingReactiveAuthenticationManager(login, oidc)

}

fun clientRegistrationBuilders() = mapOf(
    KAKAO to {
        ClientRegistration.withRegistrationId(KAKAO.clientRegistrationId)
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("http://localhost:8080/v1/login/oauth2/code/${KAKAO.clientRegistrationId}")
            .scope("profile_nickname", "account_email")
            .clientName("카카오 로그인")
            .authorizationUri("https://kauth.kakao.com/oauth/authorize")
            .tokenUri("https://kauth.kakao.com/oauth/token")
            .userInfoUri("https://kapi.kakao.com/v2/user/me")
            .userInfoAuthenticationMethod(AuthenticationMethod.HEADER)
            .userNameAttributeName("id")
    },
    NAVER to {
        ClientRegistration.withRegistrationId(NAVER.clientRegistrationId)
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("http://localhost:8080/v1/login/oauth2/code/${NAVER.clientRegistrationId}")
            .clientName("네이버 로그인")
            .authorizationUri("https://nid.naver.com/oauth2.0/authorize")
            .tokenUri("https://nid.naver.com/oauth2.0/token")
            .userInfoUri("https://openapi.naver.com/v1/nid/me")
            .userInfoAuthenticationMethod(AuthenticationMethod.HEADER)
            .userNameAttributeName("id")
    },
    GOOGLE to {
        ClientRegistration.withRegistrationId(GOOGLE.clientRegistrationId)
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("http://localhost:8080/v1/login/oauth2/code/${GOOGLE.clientRegistrationId}")
            .scope("openid", "email", "profile")
            .clientName("구글 로그인")
            .authorizationUri("https://accounts.google.com/o/oauth2/v2/auth")
            .tokenUri("https://oauth2.googleapis.com/token")
            .issuerUri("https://accounts.google.com")
            .jwkSetUri("https://www.googleapis.com/oauth2/v3/certs")
    },
    FACEBOOK to {
        ClientRegistration.withRegistrationId(FACEBOOK.clientRegistrationId)
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("http://localhost:8080/v1/login/oauth2/code/${FACEBOOK.clientRegistrationId}")
            .clientName("페이스북 로그인")
            .authorizationUri("https://www.facebook.com/v11.0/dialog/oauth")
            .tokenUri("https://graph.facebook.com/v11.0/oauth/access_token")
            .userInfoAuthenticationMethod(AuthenticationMethod.HEADER)
            .userInfoUri("https://graph.facebook.com/me")
            .userNameAttributeName("id")
    },
    GITHUB to {
        ClientRegistration.withRegistrationId(GITHUB.clientRegistrationId)
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("http://localhost:8080/v1/login/oauth2/code/${GITHUB.clientRegistrationId}")
            .clientName("깃허브 로그인")
            .authorizationUri("https://github.com/login/oauth/authorize")
            .tokenUri("https://github.com/login/oauth/access_token")
            .userInfoAuthenticationMethod(AuthenticationMethod.HEADER)
            .userInfoUri("https://api.github.com/user")
            .userNameAttributeName("id")
    }
)
