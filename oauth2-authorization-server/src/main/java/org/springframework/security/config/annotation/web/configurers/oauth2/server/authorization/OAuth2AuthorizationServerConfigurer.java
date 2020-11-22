/*
 * Copyright 2020 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization;

import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.NoUniqueBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.crypto.key.CryptoKeySource;
import org.springframework.security.oauth2.jose.jws.NimbusJwsEncoder;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenRevocationAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.web.JwkSetEndpointFilter;
import org.springframework.security.oauth2.server.authorization.web.OAuth2AuthorizationEndpointFilter;
import org.springframework.security.oauth2.server.authorization.web.OAuth2ClientAuthenticationFilter;
import org.springframework.security.oauth2.server.authorization.web.OAuth2TokenEndpointFilter;
import org.springframework.security.oauth2.server.authorization.web.OAuth2TokenRevocationEndpointFilter;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.DelegatingAuthenticationEntryPoint;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * An {@link AbstractHttpConfigurer} for OAuth 2.0 Authorization Server support.
 *
 * @author Joe Grandja
 * @see AbstractHttpConfigurer
 * @see RegisteredClientRepository
 * @see OAuth2AuthorizationService
 * @see OAuth2AuthorizationEndpointFilter
 * @see OAuth2TokenEndpointFilter
 * @see OAuth2ClientAuthenticationFilter
 * @since 0.0.1
 */
public final class OAuth2AuthorizationServerConfigurer<B extends HttpSecurityBuilder<B>>
		extends AbstractHttpConfigurer<OAuth2AuthorizationServerConfigurer<B>, B> {

	// POST&GET /oauth2/authorize 授权
	private final RequestMatcher authorizationEndpointMatcher = new OrRequestMatcher(
			new AntPathRequestMatcher(
					OAuth2AuthorizationEndpointFilter.DEFAULT_AUTHORIZATION_ENDPOINT_URI,
					HttpMethod.GET.name()),
			new AntPathRequestMatcher(
					OAuth2AuthorizationEndpointFilter.DEFAULT_AUTHORIZATION_ENDPOINT_URI,
					HttpMethod.POST.name()));
	// POST /oauth2/token 获取 token
	private final RequestMatcher tokenEndpointMatcher = new AntPathRequestMatcher(
			OAuth2TokenEndpointFilter.DEFAULT_TOKEN_ENDPOINT_URI, HttpMethod.POST.name());
	// POST /oauth2/revoke 撤消授权
	private final RequestMatcher tokenRevocationEndpointMatcher = new AntPathRequestMatcher(
			OAuth2TokenRevocationEndpointFilter.DEFAULT_TOKEN_REVOCATION_ENDPOINT_URI, HttpMethod.POST.name());
	// POST /oauth2/jwks JSON Web Key Sets 	表示一组JWK的JSON对象。JSON对象必须具有一个keys成员，该成员是JWK的数组。
	private final RequestMatcher jwkSetEndpointMatcher = new AntPathRequestMatcher(
			JwkSetEndpointFilter.DEFAULT_JWK_SET_ENDPOINT_URI, HttpMethod.GET.name());

	/**
	 * Sets the repository of registered clients. 客户端仓库
	 *
	 * @param registeredClientRepository the repository of registered clients
	 * @return the {@link OAuth2AuthorizationServerConfigurer} for further configuration
	 */
	public OAuth2AuthorizationServerConfigurer<B> registeredClientRepository(RegisteredClientRepository registeredClientRepository) {
		Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
		this.getBuilder().setSharedObject(RegisteredClientRepository.class, registeredClientRepository);
		return this;
	}

	/**
	 * Sets the authorization service. 授权(Token)管理器
	 *
	 * @param authorizationService the authorization service
	 * @return the {@link OAuth2AuthorizationServerConfigurer} for further configuration
	 */
	public OAuth2AuthorizationServerConfigurer<B> authorizationService(OAuth2AuthorizationService authorizationService) {
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		this.getBuilder().setSharedObject(OAuth2AuthorizationService.class, authorizationService);
		return this;
	}

	/**
	 * Sets the source for cryptographic keys. 密钥管理器，用于 JWKS
	 *
	 * @param keySource the source for cryptographic keys
	 * @return the {@link OAuth2AuthorizationServerConfigurer} for further configuration
	 */
	public OAuth2AuthorizationServerConfigurer<B> keySource(CryptoKeySource keySource) {
		Assert.notNull(keySource, "keySource cannot be null");
		this.getBuilder().setSharedObject(CryptoKeySource.class, keySource);
		return this;
	}

	/**
	 * Returns a {@code List} of {@link RequestMatcher}'s for the authorization server endpoints.
	 *
	 * @return a {@code List} of {@link RequestMatcher}'s for the authorization server endpoints
	 */
	public List<RequestMatcher> getEndpointMatchers() {
		return Arrays.asList(this.authorizationEndpointMatcher, this.tokenEndpointMatcher,
				this.tokenRevocationEndpointMatcher, this.jwkSetEndpointMatcher);
	}

	/**
	 * 加载顺序
	 * beforeInit();
	 * init();
	 * this.buildState = BuildState.CONFIGURING;
	 * beforeConfigure();
	 * configure();
	 * this.buildState = BuildState.BUILDING;
	 * performBuild();
	 *
	 * @see org.springframework.security.config.annotation.AbstractConfiguredSecurityBuilder
	 * doBuild()
	 */
	@Override
	public void init(B builder) {
		// postProcess: Initialize the object possibly returning a modified instance that should be used instead. 用来确保加载的永远是最新的类
		// OAUTH2.0 客户端权限管理器
		OAuth2ClientAuthenticationProvider clientAuthenticationProvider =
				new OAuth2ClientAuthenticationProvider(
						getRegisteredClientRepository(builder),
						getAuthorizationService(builder));
		builder.authenticationProvider(postProcess(clientAuthenticationProvider));

		// 需要验证 access_token 的 都需要支持 jwt
		NimbusJwsEncoder jwtEncoder = new NimbusJwsEncoder(getKeySource(builder));

		// OAUTH2.0 之 授权码 模式
		OAuth2AuthorizationCodeAuthenticationProvider authorizationCodeAuthenticationProvider =
				new OAuth2AuthorizationCodeAuthenticationProvider(
						getRegisteredClientRepository(builder),
						getAuthorizationService(builder),
						jwtEncoder);
		builder.authenticationProvider(postProcess(authorizationCodeAuthenticationProvider));

		// OAUTH2.0 之 Refresh 模式
		OAuth2RefreshTokenAuthenticationProvider refreshTokenAuthenticationProvider =
				new OAuth2RefreshTokenAuthenticationProvider(
						getAuthorizationService(builder),
						jwtEncoder);
		builder.authenticationProvider(postProcess(refreshTokenAuthenticationProvider));

		// OAUTH2.0 之 客户端认证 模式
		OAuth2ClientCredentialsAuthenticationProvider clientCredentialsAuthenticationProvider =
				new OAuth2ClientCredentialsAuthenticationProvider(
						getAuthorizationService(builder),
						jwtEncoder);
		builder.authenticationProvider(postProcess(clientCredentialsAuthenticationProvider));

		// 撤销 Token
		OAuth2TokenRevocationAuthenticationProvider tokenRevocationAuthenticationProvider =
				new OAuth2TokenRevocationAuthenticationProvider(
						getAuthorizationService(builder));
		builder.authenticationProvider(postProcess(tokenRevocationAuthenticationProvider));

		ExceptionHandlingConfigurer<B> exceptionHandling = builder.getConfigurer(ExceptionHandlingConfigurer.class);
		if (exceptionHandling != null) {
			LinkedHashMap<RequestMatcher, AuthenticationEntryPoint> entryPoints = new LinkedHashMap<>();
			entryPoints.put(
					new OrRequestMatcher(this.tokenEndpointMatcher, this.tokenRevocationEndpointMatcher),
					new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED));
			DelegatingAuthenticationEntryPoint authenticationEntryPoint =
					new DelegatingAuthenticationEntryPoint(entryPoints);

			// TODO This needs to change as the login page could be customized with a different URL
			authenticationEntryPoint.setDefaultEntryPoint(
					new LoginUrlAuthenticationEntryPoint(
							DefaultLoginPageGeneratingFilter.DEFAULT_LOGIN_PAGE_URL)); // 默认走登录

			// 如果产生异常，并且URL在 tokenEndpointMatcher/tokenRevocationEndpointMatcher 时, 则返回未授权(403)异常， 这2个URL只支持 client 的授权
			// 其它异常跳转到登陆界面
			exceptionHandling.authenticationEntryPoint(authenticationEntryPoint);
		}
	}

	@Override
	public void configure(B builder) {
		// filter chain 顺序
		// JwkSetEndpointFilter jwkSet 访问 url
		// -> OAuth2ClientAuthenticationFilter
		// -> OAuth2AuthorizationEndpointFilter
		// -> AbstractPreAuthenticatedProcessingFilter

		// Get /oauth2/jwks  返回 Jwks json
		JwkSetEndpointFilter jwkSetEndpointFilter = new JwkSetEndpointFilter(getKeySource(builder));
		builder.addFilterBefore(postProcess(jwkSetEndpointFilter), AbstractPreAuthenticatedProcessingFilter.class);

		AuthenticationManager authenticationManager = builder.getSharedObject(AuthenticationManager.class);

		// POST /oauth2/token 获取 token 使用 授权码 PKCE Flow @see https://developer.okta.com/blog/2019/08/22/okta-authjs-pkce
		// POST /oauth2/revoke 撤消授权  进行客户端权限验证
		OAuth2ClientAuthenticationFilter clientAuthenticationFilter =
				new OAuth2ClientAuthenticationFilter(
						authenticationManager,
						new OrRequestMatcher(this.tokenEndpointMatcher, this.tokenRevocationEndpointMatcher));
		builder.addFilterAfter(postProcess(clientAuthenticationFilter), AbstractPreAuthenticatedProcessingFilter.class);

		// /oauth2/authorize
		OAuth2AuthorizationEndpointFilter authorizationEndpointFilter =
				new OAuth2AuthorizationEndpointFilter(
						getRegisteredClientRepository(builder),
						getAuthorizationService(builder));
		builder.addFilterBefore(postProcess(authorizationEndpointFilter), AbstractPreAuthenticatedProcessingFilter.class);

		OAuth2TokenEndpointFilter tokenEndpointFilter =
				new OAuth2TokenEndpointFilter(
						authenticationManager,
						getAuthorizationService(builder));
		builder.addFilterAfter(postProcess(tokenEndpointFilter), FilterSecurityInterceptor.class);

		OAuth2TokenRevocationEndpointFilter tokenRevocationEndpointFilter =
				new OAuth2TokenRevocationEndpointFilter(
						authenticationManager);
		builder.addFilterAfter(postProcess(tokenRevocationEndpointFilter), OAuth2TokenEndpointFilter.class);
	}

	private static <B extends HttpSecurityBuilder<B>> RegisteredClientRepository getRegisteredClientRepository(B builder) {
		RegisteredClientRepository registeredClientRepository = builder.getSharedObject(RegisteredClientRepository.class);
		if (registeredClientRepository == null) {
			registeredClientRepository = getRegisteredClientRepositoryBean(builder);
			builder.setSharedObject(RegisteredClientRepository.class, registeredClientRepository);
		}
		return registeredClientRepository;
	}

	private static <B extends HttpSecurityBuilder<B>> RegisteredClientRepository getRegisteredClientRepositoryBean(B builder) {
		return builder.getSharedObject(ApplicationContext.class).getBean(RegisteredClientRepository.class);
	}

	private static <B extends HttpSecurityBuilder<B>> OAuth2AuthorizationService getAuthorizationService(B builder) {
		OAuth2AuthorizationService authorizationService = builder.getSharedObject(OAuth2AuthorizationService.class);
		if (authorizationService == null) {
			authorizationService = getAuthorizationServiceBean(builder);
			if (authorizationService == null) {
				authorizationService = new InMemoryOAuth2AuthorizationService();
			}
			builder.setSharedObject(OAuth2AuthorizationService.class, authorizationService);
		}
		return authorizationService;
	}

	private static <B extends HttpSecurityBuilder<B>> OAuth2AuthorizationService getAuthorizationServiceBean(B builder) {
		Map<String, OAuth2AuthorizationService> authorizationServiceMap = BeanFactoryUtils.beansOfTypeIncludingAncestors(
				builder.getSharedObject(ApplicationContext.class), OAuth2AuthorizationService.class);
		if (authorizationServiceMap.size() > 1) {
			throw new NoUniqueBeanDefinitionException(OAuth2AuthorizationService.class, authorizationServiceMap.size(),
					"Expected single matching bean of type '" + OAuth2AuthorizationService.class.getName() + "' but found " +
							authorizationServiceMap.size() + ": " + StringUtils.collectionToCommaDelimitedString(authorizationServiceMap.keySet()));
		}
		return (!authorizationServiceMap.isEmpty() ? authorizationServiceMap.values().iterator().next() : null);
	}

	private static <B extends HttpSecurityBuilder<B>> CryptoKeySource getKeySource(B builder) {
		CryptoKeySource keySource = builder.getSharedObject(CryptoKeySource.class);
		if (keySource == null) {
			keySource = getKeySourceBean(builder);
			builder.setSharedObject(CryptoKeySource.class, keySource);
		}
		return keySource;
	}

	private static <B extends HttpSecurityBuilder<B>> CryptoKeySource getKeySourceBean(B builder) {
		return builder.getSharedObject(ApplicationContext.class).getBean(CryptoKeySource.class);
	}
}
