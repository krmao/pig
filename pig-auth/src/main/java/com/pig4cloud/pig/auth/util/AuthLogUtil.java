package com.pig4cloud.pig.auth.util;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.fasterxml.jackson.datatype.jsr310.deser.LocalDateDeserializer;
import com.fasterxml.jackson.datatype.jsr310.deser.LocalDateTimeDeserializer;
import com.fasterxml.jackson.datatype.jsr310.ser.LocalDateSerializer;
import com.fasterxml.jackson.datatype.jsr310.ser.LocalDateTimeSerializer;
import com.pig4cloud.pig.auth.support.base.OAuth2ResourceOwnerBaseAuthenticationConverter;
import com.pig4cloud.pig.auth.support.base.OAuth2ResourceOwnerBaseAuthenticationToken;
import org.slf4j.Logger;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationConverter;

import javax.annotation.Nullable;
import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@SuppressWarnings("ALL")
public class AuthLogUtil {
	public static ObjectMapper getObjectMapper() {
		ObjectMapper objectMapper = new ObjectMapper();
		// jdk8日期格式支持
		DateTimeFormatter dateFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd");
		DateTimeFormatter timeFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
		Module timeModule = new JavaTimeModule()
				.addDeserializer(LocalDate.class, new LocalDateDeserializer(dateFormatter))
				.addDeserializer(LocalDateTime.class, new LocalDateTimeDeserializer(timeFormatter))
				.addSerializer(LocalDate.class, new LocalDateSerializer(dateFormatter))
				.addSerializer(LocalDateTime.class, new LocalDateTimeSerializer(timeFormatter));
		objectMapper.registerModule(timeModule);
		objectMapper.setVisibility(PropertyAccessor.ALL, JsonAutoDetect.Visibility.ANY);
		objectMapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL);
		return objectMapper;
	}

	public static @Nullable String getValueString(Object value) {
		ObjectMapper objectMapper = AuthLogUtil.getObjectMapper();
		try {
			return objectMapper.writeValueAsString(value);
		} catch (JsonProcessingException e) {
			e.printStackTrace();
		}
		return null;
	}

	public static void logValue(Logger log, String classTag, String methodTag, String key, Object value) {
//        ObjectMapper objectMapper = SpringContextHolder.getBean(ObjectMapper.class);
		ObjectMapper objectMapper = AuthLogUtil.getObjectMapper();
		try {
			log.info("|kr.mao|[{}] {} {}={}", classTag, methodTag, key, objectMapper.writeValueAsString(value));
		} catch (JsonProcessingException e) {
			e.printStackTrace();
		}
	}

	public static AuthenticationProvider wrapForShowAuthenticationProviderLogs(Logger log, AuthenticationProvider authenticationProvider) {
		return new AuthenticationProvider() {
			@Override
			public Authentication authenticate(Authentication authentication) throws AuthenticationException {
				String className = authenticationProvider.getClass().getSimpleName();
				log.info("|kr.mao|[SecurityFilterChain]({}:authenticate) >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>", className);
				log.info("|kr.mao|[SecurityFilterChain]({}:authenticate) start authentication={}", className, authentication.getPrincipal());
				Authentication result = authenticationProvider.authenticate(authentication);
				log.info("|kr.mao|[SecurityFilterChain]({}:authenticate) end authentication={}, result={}", className, authentication.getPrincipal(), result.getPrincipal());
				AuthLogUtil.logValue(log, authenticationProvider.getClass().getSimpleName(), "authentication", "result", result);
				log.info("|kr.mao|[SecurityFilterChain]({}:authenticate) <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<", className);
				return result;
			}

			@Override
			public boolean supports(Class<?> authentication) {
				boolean isSupport = authenticationProvider.supports(authentication);
				log.info("|kr.mao|[SecurityFilterChain]({}:supports) authentication={}, isSupport={}", authenticationProvider.getClass().getSimpleName(), authentication.getCanonicalName(), isSupport);
				return isSupport;
			}
		};
	}

	public static OAuth2TokenGenerator<OAuth2Token> wrapForShowOAuth2TokenGeneratorLogs(Logger log, OAuth2TokenGenerator<OAuth2Token> oAuth2TokenGenerator) {
		return new OAuth2TokenGenerator<OAuth2Token>() {
			@Override
			public OAuth2Token generate(OAuth2TokenContext context) {
				OAuth2Token token = oAuth2TokenGenerator.generate(context);
				log.info("|kr.mao|[SecurityFilterChain]({}:generate) context={}, token={}", oAuth2TokenGenerator.getClass().getSimpleName(), context.getPrincipal(), token != null ? token.getTokenValue() : null);
				return token;
			}
		};
	}

	public static AuthenticationConverter wrapForShowOAuth2ResourceOwnerBaseAuthenticationConverterLogs(Logger log, AuthenticationConverter converter) {
		if (converter instanceof OAuth2ResourceOwnerBaseAuthenticationConverter) {
			OAuth2ResourceOwnerBaseAuthenticationConverter wrapConverter = (OAuth2ResourceOwnerBaseAuthenticationConverter) converter;
			return new OAuth2ResourceOwnerBaseAuthenticationConverter<OAuth2ResourceOwnerBaseAuthenticationToken>() {

				public boolean support(String grantType) {
					boolean isSupport = wrapConverter.support(grantType);
					log.info("|kr.mao|[SecurityFilterChain]({}:support) grantType={}, isSupport={}", converter.getClass().getSimpleName(), grantType, isSupport);
					return isSupport;
				}

				@Override
				public OAuth2ResourceOwnerBaseAuthenticationToken buildToken(Authentication clientPrincipal, Set<String> requestedScopes, Map<String, Object> additionalParameters) {
					OAuth2ResourceOwnerBaseAuthenticationToken token = wrapConverter.buildToken(clientPrincipal, requestedScopes, additionalParameters);
					log.info("|kr.mao|[SecurityFilterChain]({}:buildToken) clientPrincipal={}, requestedScopes={} additionalParameters={} token={}", converter.getClass().getSimpleName(), clientPrincipal, requestedScopes, additionalParameters, token);
					return token;
				}

				@Override
				public void checkParams(HttpServletRequest request) {
					wrapConverter.checkParams(request);
					log.info("|kr.mao|[SecurityFilterChain]({}:checkParams) request={}", converter.getClass().getSimpleName(), request.getRequestURI());
				}
			};
		} else {
			return new AuthenticationConverter() {
				@Override
				public Authentication convert(HttpServletRequest request) {
					return converter.convert(request);
				}
			};
		}
	}

	public static SecurityFilterChain wrapForShowSecurityFilterChainLogs(Logger log, SecurityFilterChain chain) {
		return new SecurityFilterChain() {
			@Override
			public boolean matches(HttpServletRequest request) {
				log.info("|kr.mao|[SecurityFilterChain](matches) url={}, query={}", request.getRequestURI(), request.getQueryString());
				return chain.matches(request);
			}

			@Override
			public List<Filter> getFilters() {
				log.info("|kr.mao|[SecurityFilterChain](getFilters) filters={}", chain.getFilters().stream().map(item -> item.getClass().getSimpleName()).collect(Collectors.toList()));
				return chain.getFilters().stream().map(item -> new Filter() {
					@Override
					public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
						String filterName = item.getClass().getSimpleName();
						log.info("|kr.mao|[SecurityFilterChain](filter:{}) doFilter before, {}", String.format("%-47s", filterName), AuthLogUtil.getFilterDescription(filterName));
						item.doFilter(request, response, chain);
						log.info("|kr.mao|[SecurityFilterChain](filter:{}) doFilter after", String.format("%-47s", filterName));

					}
				}).collect(Collectors.toList());
			}
		};
	}

	/**
	 * 获取 Filter 的描述信息<br/>
	 * jdk 1.8 switch 支持 string
	 *
	 * @see <a href="https://zhuanlan.zhihu.com/p/665648469">SpringSecurity6 | 核心过滤器</a>
	 * @see <a href="https://blog.csdn.net/qq_44444470/article/details/133089941">SpringSecurity的默认Filter详解</a>
	 * <p>
	 * =================================================================
	 * <p>
	 * - pig master cloud
	 * ---- DisableEncodeUrlFilter,
	 * ---- WebAsyncManagerIntegrationFilter,
	 * ---- AuthorizationServerContextFilter,
	 * ---- SecurityContextPersistenceFilter,
	 * ---- HeaderWriterFilter,
	 * ---- LogoutFilter,
	 * ---- OAuth2AuthorizationServerMetadataEndpointFilter,
	 * ---- OAuth2AuthorizationEndpointFilter,
	 * ---- OAuth2ClientAuthenticationFilter,
	 * <p>
	 * ---- ValidateCodeFilter,
	 * ---- PasswordDecoderFilter,
	 * ---- UsernamePasswordAuthenticationFilter,
	 * <p>
	 * ---- RequestCacheAwareFilter,
	 * ---- SecurityContextHolderAwareRequestFilter,
	 * ---- AnonymousAuthenticationFilter,
	 * ---- SessionManagementFilter,
	 * ---- ExceptionTranslationFilter,
	 * <p>
	 * ---- FilterSecurityInterceptor,
	 * <p>
	 * ---- OAuth2TokenEndpointFilter,
	 * ---- OAuth2TokenIntrospectionEndpointFilter,
	 * ---- OAuth2TokenRevocationEndpointFilter
	 * <p>
	 * =================================================================
	 * <p>
	 * - pig master boot
	 * ---- DisableEncodeUrlFilter
	 * ---- WebAsyncManagerIntegrationFilter
	 * ---- AuthorizationServerContextFilter
	 * ---- SecurityContextPersistenceFilter
	 * ---- HeaderWriterFilter
	 * ---- LogoutFilter
	 * ---- OAuth2AuthorizationServerMetadataEndpointFilter
	 * ---- OAuth2AuthorizationEndpointFilter
	 * ---- OAuth2ClientAuthenticationFilter
	 * <p>
	 * ---- PasswordDecoderFilter
	 * ---- ValidateCodeFilter
	 * ---- BearerTokenAuthenticationFilter
	 * <p>
	 * ---- RequestCacheAwareFilter
	 * ---- SecurityContextHolderAwareRequestFilter
	 * ---- AnonymousAuthenticationFilter
	 * ---- SessionManagementFilter
	 * ---- ExceptionTranslationFilter
	 * ---- OAuth2TokenEndpointFilter
	 * ---- OAuth2TokenIntrospectionEndpointFilter
	 * ---- OAuth2TokenRevocationEndpointFilter
	 * <p>
	 * ---- AuthorizationFilter
	 * <p>
	 * =================================================================
	 */
	public static String getFilterDescription(String filterName) {
		switch (filterName) {
			case "DisableEncodeUrlFilter":
				return "阻止Spring Security对URL进行自动编码, 从而使得URL可以保持原始状态(Cookie被禁用时, 后端响应将sessionId拼接在URL后进行重写传递给页面, DisableEncodeUrlFilter阻止这容易造成信息泄露的行为), 禁用后可能造成 防止跨站脚本（XSS）攻击 等安全问题";
			case "WebAsyncManagerIntegrationFilter":
				return "通过创建拦截器的形式, 将安全上下文securityContextHolderStrategy正确的传递给子线程(因为在异步处理中, 线程可能会发生切换), 后续子线程可以通过该拦截器获取到用户认证信息";
			case "AuthorizationServerContextFilter":
				return "将 AuthorizationServerContext 关联到 AuthorizationServerContextHolder";
			case "SecurityContextPersistenceFilter":
				return "请求来临时关联 SecurityContextHolder.setContext(contextBeforeChainExecution) 上下文信息, 请求结束时清空 SecurityContextHolder.clearContext() 上下文信息, 避免了用户直接从 Session 中获取安全上下文信息, 而是从 SecurityContextHolder 中获取";
			case "HeaderWriterFilter":
				return "将某些头信息添加到响应中, 添加某些启用浏览器保护的头信息非常有用, 如X-Frame-Options、X-XSS-Protection、X-Content-Type-Options等, 增加一些安全性";
			case "LogoutFilter":
				return "处理用户注销请求, 清除用户的认证信息、使当前会话失效、清空安全上下文等, 然后将用户重定向到指定的页面或者直接返回注销成功的响应";
			case "OAuth2AuthorizationServerMetadataEndpointFilter":
				return "对外提供授权服务器元信息的端点, 遵循RFC8414相关的规范, 会把授权服务器元数据对象 OAuth2AuthorizationServerMetadata 以JSON的形式返回给 OAuth2 客户端";
			case "OAuth2AuthorizationEndpointFilter":
				return "【负责用户(非客户端)与授权服务器之间的授权流程】客户端是指向授权服务器请求访问令牌的应用程序或服务...... 在 OAuth 2.0 中 授权流程通常涉及三方: 客户端应用程序、授权服务器和资源所有者（用户）, OAuth 2.0 的主要目的是允许客户端应用程序代表资源所有者访问受保护的资源...... OAuth2AuthorizationEndpointFilter 主要处理的是用户与授权服务器之间的交互，因为在授权过程中，用户通常需要向授权服务器提供授权或认证信息，例如登录凭据或授权同意。授权端点通常负责处理这些用户与授权服务器之间的交互，以便授权服务器可以生成授权码或令牌，并将其返回给客户端应用程序...... 处理OAuth 2.0 Authorization Code Grant 授权请求 /oauth2/authorize, 包含用户二次确认（Consent）逻辑";
			case "OAuth2ClientAuthenticationFilter":
				return "【负责客户端认证(非用户), 认证后获取客户端信息】OAuth 2.0 客户端认证过滤器, 判断是否是一个有效的认证请求(调用 RegisteredClientRepository(数据库存储, 自定义实现为 RemoteRegisteredClientRepository)来判断), 如果有效则开始认证, 成功返回 token, 失败或者客户端id无效返回错误信息, 如果不是一个有效的认证请求, 则继续其他的过滤器链, 主要负责客户端的认证, 用户名密码认证最好也是放在这里, 客户端认证通过后紧接着进行用户名密码认证, 不过本项目是放在 OAuth2TokenEndpointFilter 中进行用户认证 OAuth2TokenEndpointFilter-> authorizationServerConfigurer.tokenEndpoint(AuthorizationServerConfiguration:authorizationServerSecurityFilterChain 中配置) -> tokenEndpoint.accessTokenRequestConverter(accessTokenRequestConverter()) -> accessTokenRequestConverter";
			case "UsernamePasswordAuthenticationFilter":
				return "传统的表单用户名密码认证, 虽然隶属于 spring security, 但是与 OAuth2.0 没有直接关系, OAuth2.0四种模式中的用户名密码模式跟这个 UsernamePasswordAuthenticationFilter 没有一点关系, 如果是OAuth2.0 的用户名密码模式可以直接禁用(http.httpBasic().disable();http.formLogin().disable();注释掉 apply(new FormIdentityLoginConfigurer())) UsernamePasswordAuthenticationFilter, 而不影响 token 的发放和用户信息的获取...... 专门负责对传统表单非 OAuth2.0 用户提交的用户名密码信息进行身份认证, 并在认证成功后生成认证信息保存到上下文中, 供后续 OAuth2TokenEndpointFilter 生成令牌时调用, 在大多数情况下认证信息首先由 UsernamePasswordAuthenticationFilter 进行处理并放置在安全上下文中, 这是因为其是专门用于处理用户身份认证的过滤器, 它负责从用户提交的用户名密码信息进行认证, 并生成相应的认证信息, 然后将认证信息存储在安全上下文中, 供后续的请求处理过程使用, 而 OAuth2TokenEndpointFilter 主要用于处理 OAuth 2.0 令牌颁发请求, 它并不负责用户身份认证的过程, 通常情况下 OAuth 2.0 令牌颁发请求需要携带已经认证过的用户信息, 并且这些信息通常是由 UsernamePasswordAuthenticationFilter 在之前的请求中进行认证并放置在安全上下文中的, 如果将认证信息放置在 OAuth2TokenEndpointFilter 中, 这可能会导致逻辑上的混淆, 并且违反了单一责任原则, 此外 OAuth2TokenEndpointFilter 并不是专门用于处理用户认证的过滤器, 因此放置认证信息在这里可能不是最佳实践, 因此通常情况下应该将认证信息放置在 UsernamePasswordAuthenticationFilter 中, 并且 OAuth2TokenEndpointFilter 用于处理令牌颁发请求, 这样做有助于保持代码的清晰性和一致性, 并且更符合常见的安全认证模式";
			case "RequestCacheAwareFilter":
				return "实现用户完成身份验证后能够无缝地继续之前缓存的被登录打断的请求的处理流程, 优先使用缓存中的请求";
			case "SecurityContextHolderAwareRequestFilter":
				return "将安全上下文信息与请求关联, 实现在请求处理过程中方便地获取和操作安全上下文信息";
			case "AnonymousAuthenticationFilter":
				return "当之前的过滤器没有发现认证的用户信息时创建一个匿名用户, 允许匿名用户在系统中进行一定程度的操作，比如访问公开的资源或进行有限制的操作";
			case "SessionManagementFilter":
				return "将 SecurityContextRepository 的内容与 SecurityContextHolder 的当前内容进行对照, 以确定用户在当前请求中是否已被认证, 如果 repository 包含一个 security context, 那么 filter 什么也不做, 如果不包含而 thread-local 的 SecurityContext 包含一个（非匿名的）Authentication 对象, 那么 filter 就会认为他们已经被栈中的前一个 filter 认证了, 然后将调用配置的 SessionAuthenticationStrategy, 如果用户当前没有被认证, filter 将检查是否有无效的会话 invalid session ID 被请求(例如因为超时), 并将调用配置的 InvalidSessionStrategy";
			case "ExceptionTranslationFilter":
				return "实现对各种安全异常的统一处理和响应定制, 将异常转换为特定的响应, 比如跳转到登录页面、返回拒绝访问的错误信息等";
			case "FilterSecurityInterceptor":
				return "负责将之前 Filter 产生的认证信息从当前请求上下文中取出来, 对请求的资源做权限判断, 如果无权访问相应的资源则抛出 spring-security 异常, 由 ExceptionTranslationFilter 进行处理";
			case "OAuth2TokenEndpointFilter":
				return "【负责用户认证后的Token生成(本项目用户认证操作也在这个过滤器中)】(因为有 authorizationServerConfigurer.tokenEndpoint 这样的便捷方法可以使用, 所以用户认证逻辑放在这里, 虽然违反了单一原则, 但是方便啊, 可以直接用默认配置 OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http), 而 OAuth2AuthorizationEndpointFilter 没有相关的便捷方法, 需要自定义过滤器, 并且自定义过滤器链, 所以不能直接使用 applyDefaultSecurity 的默认过滤器链, 而需要完全自定义, 太麻烦了, 这可能也是本项目 用户认证逻辑写在 OAuth2TokenEndpointFilter 中的原因)...... 负责颁发令牌(token), 判断是否是令牌颁发请求, 如果不是则跳过继续后面的 Filter, 如果是则根据之前 Filter(OAuth2ClientAuthenticationFilter) 产生的认证信息以及对应的颁发策略生成 token(如果 UsernamePasswordAuthenticationFilter 已经认证成功, 则这里无需重复认证, 通过上下文获取认证信息, 直接生成 token), 每种策略实际就是一个 AuthenticationConverter 搭配一个 AuthenticationProvider 组合而成, 一个负责解析请求参数, 一个负责处理请求参数, authorizationServerConfigurer.tokenEndpoint() 中的配置影响的是令牌端点的处理行为，而令牌端点的实际处理是在 OAuth2TokenEndpointFilter 中完成的。因此，tokenEndpoint 中的配置会在 OAuth2TokenEndpointFilter 之后执行, 用户认证操作在 tokenEndpoint.accessTokenRequestConverter(accessTokenRequestConverter()) 中执行...... 总结:将用户认证放在 OAuth2ClientAuthenticationFilter 中确实更为合适，因为这个过滤器专门用于处理客户端的认证请求。在 OAuth2 中，客户端通常是指向授权服务器请求访问令牌的应用程序或服务，而不是最终用户。虽然你可以将用户认证放在 OAuth2TokenEndpointFilter 中，但这可能会违反单一责任原则，因为 OAuth2TokenEndpointFilter 的主要责任是处理令牌端点的请求，而不是处理用户身份认证。在实践中，如果你有特殊的需求需要将用户认证放在 OAuth2TokenEndpointFilter 中，例如需要在令牌端点处理过程中完成用户认证并且没有其他合适的地方，那么你也可以这样做。但是，最好的做法是遵循最佳实践，将用户认证放在专门处理客户端认证的过滤器中，例如 OAuth2ClientAuthenticationFilter。这样可以使代码更加清晰、易于理解和维护";
			case "OAuth2TokenIntrospectionEndpointFilter":
				return "处理令牌自省逻辑, 用于验证和获取关于 token 的详细信息, 通过内省端点, 资源服务器可以向授权服务器查询一个访问令牌的状态和相关元数据, 验证令牌的有效性, 确保安全性和合规性";
			case "OAuth2TokenRevocationEndpointFilter":
				return "处理令牌撤销逻辑, 允许客户端或资源所有者主动撤销访问令牌和刷新令牌, 从而使它们立即失效";
			default:
				return "未知的过滤器: " + filterName;
		}
	}
}
