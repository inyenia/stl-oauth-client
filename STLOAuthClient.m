//
//  AFOAuth1Client.m
//
//  Created by Joel Chen on 3/4/14.
//  Copyright (c) 2014 Joel Chen [http://lnkd.in/bwwnBWR]
//

#import "STLOAuthClient.h"
#import "AFNetworking.h"

#import <CommonCrypto/CommonHMAC.h>

static NSString * const kAFOAuth1Version = @"1.0";
NSString * const kAFApplicationLaunchedWithURLNotification = @"kAFApplicationLaunchedWithURLNotification";
#if __IPHONE_OS_VERSION_MIN_REQUIRED
NSString * const kAFApplicationLaunchOptionsURLKey = @"UIApplicationLaunchOptionsURLKey";
#else
NSString * const kAFApplicationLaunchOptionsURLKey = @"NSApplicationLaunchOptionsURLKey";
#endif

static NSString * AFEncodeBase64WithData(NSData *data) {
	NSUInteger length = [data length];
	NSMutableData *mutableData = [NSMutableData dataWithLength:((length + 2) / 3) * 4];
	
	uint8_t *input = (uint8_t *)[data bytes];
	uint8_t *output = (uint8_t *)[mutableData mutableBytes];
	
	for (NSUInteger i = 0; i < length; i += 3) {
		NSUInteger value = 0;
		for (NSUInteger j = i; j < (i + 3); j++) {
			value <<= 8;
			if (j < length) {
				value |= (0xFF & input[j]);
			}
		}
		
		static uint8_t const kAFBase64EncodingTable[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
		
		NSUInteger idx = (i / 3) * 4;
		output[idx + 0] = kAFBase64EncodingTable[(value >> 18) & 0x3F];
		output[idx + 1] = kAFBase64EncodingTable[(value >> 12) & 0x3F];
		output[idx + 2] = (i + 1) < length ? kAFBase64EncodingTable[(value >> 6)  & 0x3F] : '=';
		output[idx + 3] = (i + 2) < length ? kAFBase64EncodingTable[(value >> 0)  & 0x3F] : '=';
	}
	
	return [[NSString alloc] initWithData:mutableData encoding:NSASCIIStringEncoding];
}

static NSString * AFPercentEscapedQueryStringPairMemberFromStringWithEncoding(NSString *string, NSStringEncoding encoding) {
	static NSString * const kAFCharactersToBeEscaped = @":/?&=;+!@#$()',*";
	static NSString * const kAFCharactersToLeaveUnescaped = @"[].";
	
	return (__bridge_transfer NSString *)CFURLCreateStringByAddingPercentEscapes(kCFAllocatorDefault, (__bridge CFStringRef)string, (__bridge CFStringRef)kAFCharactersToLeaveUnescaped, (__bridge CFStringRef)kAFCharactersToBeEscaped, CFStringConvertNSStringEncodingToEncoding(encoding));
}

static NSDictionary * AFParametersFromQueryString(NSString *queryString) {
	NSMutableDictionary *parameters = [NSMutableDictionary dictionary];
	if (queryString) {
		NSScanner *parameterScanner = [[NSScanner alloc] initWithString:queryString];
		NSString *name = nil;
		NSString *value = nil;
		
		while (![parameterScanner isAtEnd]) {
			name = nil;
			[parameterScanner scanUpToString:@"=" intoString:&name];
			[parameterScanner scanString:@"=" intoString:NULL];
			
			value = nil;
			[parameterScanner scanUpToString:@"&" intoString:&value];
			[parameterScanner scanString:@"&" intoString:NULL];
			
			if (name && value) {
				parameters[[name stringByReplacingPercentEscapesUsingEncoding:NSUTF8StringEncoding]] = [value stringByReplacingPercentEscapesUsingEncoding:NSUTF8StringEncoding];
			}
		}
	}
	
	return parameters;
}

static inline BOOL AFQueryStringValueIsTrue(NSString *value) {
	return value && [[value lowercaseString] hasPrefix:@"t"];
}

static inline NSString * AFNounce() {
	CFUUIDRef uuid = CFUUIDCreate(NULL);
	CFStringRef string = CFUUIDCreateString(NULL, uuid);
	CFRelease(uuid);
	
	return (NSString *)CFBridgingRelease(string);
}

static inline NSString * NSStringFromAFOAuthSignatureMethod(AFOAuthSignatureMethod signatureMethod) {
	switch (signatureMethod) {
		case AFPlainTextSignatureMethod:
			return @"PLAINTEXT";
		case AFHMACSHA1SignatureMethod:
			return @"HMAC-SHA1";
		default:
			return nil;
	}
}

static inline NSString * AFPlainTextSignature(NSURLRequest *request, NSString *consumerSecret, NSString *tokenSecret, NSStringEncoding stringEncoding) {
	NSString *secret = tokenSecret ? tokenSecret : @"";
	NSString *signature = [NSString stringWithFormat:@"%@&%@", consumerSecret, secret];
	return signature;
}

static inline NSString * AFHMACSHA1Signature(NSURLRequest *request, NSString *consumerSecret, NSString *tokenSecret, NSStringEncoding stringEncoding) {
	NSString *secret = tokenSecret ? tokenSecret : @"";
	NSString *secretString = [NSString stringWithFormat:@"%@&%@", AFPercentEscapedQueryStringPairMemberFromStringWithEncoding(consumerSecret, stringEncoding), AFPercentEscapedQueryStringPairMemberFromStringWithEncoding(secret, stringEncoding)];
	NSData *secretStringData = [secretString dataUsingEncoding:stringEncoding];
	
	NSString *queryString = AFPercentEscapedQueryStringPairMemberFromStringWithEncoding([[[[[request URL] query] componentsSeparatedByString:@"&"] sortedArrayUsingSelector:@selector(compare:)] componentsJoinedByString:@"&"], stringEncoding);
	NSString *requestString = [NSString stringWithFormat:@"%@&%@&%@", [request HTTPMethod], AFPercentEscapedQueryStringPairMemberFromStringWithEncoding([[[request URL] absoluteString] componentsSeparatedByString:@"?"][0], stringEncoding), queryString];
	NSData *requestStringData = [requestString dataUsingEncoding:stringEncoding];
	
	uint8_t digest[CC_SHA1_DIGEST_LENGTH];
	CCHmacContext cx;
	CCHmacInit(&cx, kCCHmacAlgSHA1, [secretStringData bytes], [secretStringData length]);
	CCHmacUpdate(&cx, [requestStringData bytes], [requestStringData length]);
	CCHmacFinal(&cx, digest);
	
	return AFEncodeBase64WithData([NSData dataWithBytes:digest length:CC_SHA1_DIGEST_LENGTH]);
}

NSString * const kAFOAuth1CredentialServiceName = @"AFOAuthCredentialService";

static NSDictionary * AFKeychainQueryDictionaryWithIdentifier(NSString *identifier) {
	return @{(__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
			 (__bridge id)kSecAttrAccount: identifier,
			 (__bridge id)kSecAttrService: kAFOAuth1CredentialServiceName
			 };
}

@implementation STLOAuthClient

- (id)initWithBaseURL:(NSURL *)url
				  consumerKey:(NSString *)consumerKey
			   consumerSecret:(NSString *)consumerSecret
						token:(NSString *)token
		          tokenSecret:(NSString *)tokenSecret
{
	NSParameterAssert(consumerKey);
	NSParameterAssert(consumerSecret);
	
	self = [super init];
	if (!self) {
		return nil;
	}
	
	self.url = url;
	self.consumerKey = consumerKey;
	self.consumerSecret = consumerSecret;
	self.signatureMethod = AFHMACSHA1SignatureMethod;
	self.defaultHeaders = [NSMutableDictionary dictionary];
	self.parameterEncoding = AFFormURLParameterEncoding;
	self.stringEncoding = NSUTF8StringEncoding;
	self.responseSerializer = [AFHTTPResponseSerializer serializer];
	self.token = token;
	self.tokenSecret = tokenSecret;
	
	// Accept-Language HTTP Header; see http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.4
	NSMutableArray *acceptLanguagesComponents = [NSMutableArray array];
	[[NSLocale preferredLanguages] enumerateObjectsUsingBlock:^(id obj, NSUInteger idx, BOOL *stop) {
		float q = 1.0f - (idx * 0.1f);
		[acceptLanguagesComponents addObject:[NSString stringWithFormat:@"%@;q=%0.1g", obj, q]];
		*stop = q <= 0.5f;
	}];
	[self setDefaultHeader:@"Accept-Language" value:[acceptLanguagesComponents componentsJoinedByString:@", "]];
	
	NSString *userAgent = nil;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu"
#if defined(__IPHONE_OS_VERSION_MIN_REQUIRED)
	// User-Agent Header; see http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.43
	userAgent = [NSString stringWithFormat:@"%@/%@ (%@; iOS %@; Scale/%0.2f)", [[[NSBundle mainBundle] infoDictionary] objectForKey:(__bridge NSString *)kCFBundleExecutableKey] ?: [[[NSBundle mainBundle] infoDictionary] objectForKey:(__bridge NSString *)kCFBundleIdentifierKey], (__bridge id)CFBundleGetValueForInfoDictionaryKey(CFBundleGetMainBundle(), kCFBundleVersionKey) ?: [[[NSBundle mainBundle] infoDictionary] objectForKey:(__bridge NSString *)kCFBundleVersionKey], [[UIDevice currentDevice] model], [[UIDevice currentDevice] systemVersion], ([[UIScreen mainScreen] respondsToSelector:@selector(scale)] ? [[UIScreen mainScreen] scale] : 1.0f)];
#elif defined(__MAC_OS_X_VERSION_MIN_REQUIRED)
	userAgent = [NSString stringWithFormat:@"%@/%@ (Mac OS X %@)", [[[NSBundle mainBundle] infoDictionary] objectForKey:(__bridge NSString *)kCFBundleExecutableKey] ?: [[[NSBundle mainBundle] infoDictionary] objectForKey:(__bridge NSString *)kCFBundleIdentifierKey], [[[NSBundle mainBundle] infoDictionary] objectForKey:@"CFBundleShortVersionString"] ?: [[[NSBundle mainBundle] infoDictionary] objectForKey:(__bridge NSString *)kCFBundleVersionKey], [[NSProcessInfo processInfo] operatingSystemVersionString]];
#endif
#pragma clang diagnostic pop
	if (userAgent) {
		if (![userAgent canBeConvertedToEncoding:NSASCIIStringEncoding]) {
			NSMutableString *mutableUserAgent = [userAgent mutableCopy];
			CFStringTransform((__bridge CFMutableStringRef)(mutableUserAgent), NULL, kCFStringTransformToLatin, false);
			userAgent = mutableUserAgent;
		}
		[self setDefaultHeader:@"User-Agent" value:userAgent];
	}
	
	return self;
}

- (void)dealloc {
	self.applicationLaunchNotificationObserver = nil;
}

- (void)setApplicationLaunchNotificationObserver:(id)applicationLaunchNotificationObserver {
	if (_applicationLaunchNotificationObserver) {
		[[NSNotificationCenter defaultCenter] removeObserver:_applicationLaunchNotificationObserver];
	}
	
	[self willChangeValueForKey:@"applicationLaunchNotificationObserver"];
	_applicationLaunchNotificationObserver = applicationLaunchNotificationObserver;
	[self didChangeValueForKey:@"applicationLaunchNotificationObserver"];
}

- (void)setDefaultHeader:(NSString *)header value:(NSString *)value {
	[self.defaultHeaders setValue:value forKey:header];
}

- (NSDictionary *)OAuthParameters {
	NSMutableDictionary *parameters = [NSMutableDictionary dictionary];
	parameters[@"oauth_version"] = kAFOAuth1Version;
	parameters[@"oauth_signature_method"] = NSStringFromAFOAuthSignatureMethod(self.signatureMethod);
	parameters[@"oauth_consumer_key"] = self.consumerKey;
	parameters[@"oauth_timestamp"] = [@(floor([[NSDate date] timeIntervalSince1970])) stringValue];
	parameters[@"oauth_nonce"] = AFNounce();
	
	if (self.realm) {
		parameters[@"realm"] = self.realm;
	}
	
	return parameters;
}

- (NSString *)OAuthSignatureForMethod:(NSString *)method
								 path:(NSString *)path
						   parameters:(NSDictionary *)parameters
{
	NSMutableURLRequest *request = [self encodedRequestWithMethod:@"GET" path:path parameters:parameters];
	[request setHTTPMethod:method];
	
	switch (self.signatureMethod) {
		case AFPlainTextSignatureMethod:
			return AFPlainTextSignature(request, self.consumerSecret, self.tokenSecret, self.stringEncoding);
		case AFHMACSHA1SignatureMethod:
			return AFHMACSHA1Signature(request, self.consumerSecret, self.tokenSecret, self.stringEncoding);
		default:
			return nil;
	}
}

+ (NSString *)queryStringFromParameters:(NSDictionary *)parameters encoding:(NSStringEncoding)stringEncoding {
	NSMutableArray *entries = [NSMutableArray array];
	[parameters enumerateKeysAndObjectsUsingBlock:^(id key, id obj, BOOL *stop) {
		NSString *entry = [NSString stringWithFormat:@"%@=%@", AFPercentEscapedQueryStringPairMemberFromStringWithEncoding(key, stringEncoding), AFPercentEscapedQueryStringPairMemberFromStringWithEncoding(obj, stringEncoding)];
		[entries addObject:entry];
	}];
	return [entries componentsJoinedByString:@"&"];
}

- (NSString *)authorizationHeaderForMethod:(NSString *)method
									  path:(NSString *)path
								parameters:(NSDictionary *)parameters
{
	static NSString * const kAFOAuth1AuthorizationFormatString = @"OAuth %@";
	
	NSMutableDictionary *mutableParameters = parameters ? [parameters mutableCopy] : [NSMutableDictionary dictionary];
	NSMutableDictionary *mutableAuthorizationParameters = [NSMutableDictionary dictionary];
	
	if (self.consumerKey && self.consumerSecret) {
		[mutableAuthorizationParameters addEntriesFromDictionary:[self OAuthParameters]];
		if (self.token) {
			mutableAuthorizationParameters[@"oauth_token"] = self.token;
		}
	}
	
	[mutableParameters enumerateKeysAndObjectsUsingBlock:^(id key, id obj, BOOL *stop) {
		if ([key isKindOfClass:[NSString class]] && [key hasPrefix:@"oauth_"]) {
			mutableAuthorizationParameters[key] = obj;
		}
	}];
	
	[mutableParameters addEntriesFromDictionary:mutableAuthorizationParameters];
	mutableAuthorizationParameters[@"oauth_signature"] = [self OAuthSignatureForMethod:method path:path parameters:mutableParameters];
	NSArray *sortedComponents = [[[STLOAuthClient queryStringFromParameters:mutableAuthorizationParameters encoding:self.stringEncoding] componentsSeparatedByString:@"&"] sortedArrayUsingSelector:@selector(caseInsensitiveCompare:)];
	NSMutableArray *mutableComponents = [NSMutableArray array];
	for (NSString *component in sortedComponents) {
		NSArray *subcomponents = [component componentsSeparatedByString:@"="];
		if ([subcomponents count] == 2) {
			[mutableComponents addObject:[NSString stringWithFormat:@"%@=\"%@\"", subcomponents[0], subcomponents[1]]];
		}
	}
	
	return [NSString stringWithFormat:kAFOAuth1AuthorizationFormatString, [mutableComponents componentsJoinedByString:@", "]];
}

#pragma mark -

- (void)setServiceProviderRequestHandler:(void (^)(NSURLRequest *request))block
							  completion:(void (^)())completion
{
	self.serviceProviderRequestHandler = block;
	self.serviceProviderRequestCompletion = completion;
}

#pragma mark - AFHTTPClient

- (NSMutableURLRequest *)encodedRequestWithMethod:(NSString *)method
											 path:(NSString *)path
									   parameters:(NSDictionary *)parameters
{
	NSParameterAssert(method);
	
	if (!path) {
		path = @"";
	}
	
	NSURL *url = [NSURL URLWithString:path relativeToURL:self.url];
	NSMutableURLRequest *request = [[NSMutableURLRequest alloc] initWithURL:url];
	[request setHTTPMethod:method];
	[request setAllHTTPHeaderFields:self.defaultHeaders];
	
	if (parameters) {
		if ([method isEqualToString:@"GET"] || [method isEqualToString:@"HEAD"] || [method isEqualToString:@"DELETE"]) {
			url = [NSURL URLWithString:[[url absoluteString] stringByAppendingFormat:[path rangeOfString:@"?"].location == NSNotFound ? @"?%@" : @"&%@", [STLOAuthClient queryStringFromParameters:parameters encoding:self.stringEncoding]]];
			[request setURL:url];
		} else {
			NSString *charset = (__bridge NSString *)CFStringConvertEncodingToIANACharSetName(CFStringConvertNSStringEncodingToEncoding(self.stringEncoding));
			NSError *error = nil;
			
			switch (self.parameterEncoding) {
				case AFFormURLParameterEncoding:
					[request setValue:[NSString stringWithFormat:@"application/x-www-form-urlencoded; charset=%@", charset] forHTTPHeaderField:@"Content-Type"];
					[request setHTTPBody:[[STLOAuthClient queryStringFromParameters:parameters encoding:self.stringEncoding] dataUsingEncoding:self.stringEncoding]];
					break;
				case AFJSONParameterEncoding:
					[request setValue:[NSString stringWithFormat:@"application/json; charset=%@", charset] forHTTPHeaderField:@"Content-Type"];
					[request setHTTPBody:[NSJSONSerialization dataWithJSONObject:parameters options:(NSJSONWritingOptions)0 error:&error]];
					break;
				case AFPropertyListParameterEncoding:
					[request setValue:[NSString stringWithFormat:@"application/x-plist; charset=%@", charset] forHTTPHeaderField:@"Content-Type"];
					[request setHTTPBody:[NSPropertyListSerialization dataWithPropertyList:parameters format:NSPropertyListXMLFormat_v1_0 options:0 error:&error]];
					break;
			}
			
			if (error) {
				NSLog(@"%@ %@: %@", [self class], NSStringFromSelector(_cmd), error);
			}
		}
	}
	
	return request;
}

- (NSMutableURLRequest *)requestWithMethod:(NSString *)method
									  path:(NSString *)path
								parameters:(NSDictionary *)parameters
{
	NSMutableDictionary *mutableParameters = [parameters mutableCopy];
	[mutableParameters addEntriesFromDictionary:[[self OAuthParameters] mutableCopy]];
	if (self.token) {
		mutableParameters[@"oauth_token"] = self.token;
	}
	
	NSDictionary *parametersCopy = [mutableParameters mutableCopy];
	for (NSString *key in parametersCopy) {
		if ([key hasPrefix:@"oauth_"]) {
			[mutableParameters removeObjectForKey:key];
		}
	}
	
	NSMutableURLRequest *request = [self encodedRequestWithMethod:method path:path parameters:mutableParameters];
	
	// Only use parameters in the request entity body (with a content-type of `application/x-www-form-urlencoded`).
	// See RFC 5849, Section 3.4.1.3.1 http://tools.ietf.org/html/rfc5849#section-3.4
	NSMutableDictionary *authorizationParameters = [parameters mutableCopy];
	if (!([method isEqualToString:@"GET"] || [method isEqualToString:@"HEAD"] || [method isEqualToString:@"DELETE"])) {
		if ([[request valueForHTTPHeaderField:@"Content-Type"] hasPrefix:@"application/x-www-form-urlencoded"]) {
			authorizationParameters = parameters;
		}else{
			authorizationParameters = [[self OAuthParameters] mutableCopy];
			if (self.token) {
				authorizationParameters[@"oauth_token"] = self.token;
			}
		}
	}
	
	[request setValue:[self authorizationHeaderForMethod:method path:path parameters:authorizationParameters] forHTTPHeaderField:@"Authorization"];
	[request setHTTPShouldHandleCookies:NO];
	
	return request;
}

- (NSMutableURLRequest *)multipartFormRequestWithMethod:(NSString *)method
												   path:(NSString *)path
											 parameters:(NSDictionary *)parameters
							  constructingBodyWithBlock:(void (^)(id <AFMultipartFormData> formData))block
{
	
	NSMutableDictionary *mutableParameters = [parameters mutableCopy];
	[mutableParameters addEntriesFromDictionary:[[self OAuthParameters] mutableCopy]];
	if (self.token) {
		mutableParameters[@"oauth_token"] = self.token;
	}
	
	NSDictionary *parametersCopy = [mutableParameters mutableCopy];
	for (NSString *key in parametersCopy) {
		if ([key hasPrefix:@"oauth_"]) {
			[mutableParameters removeObjectForKey:key];
		}
	}
	
	NSMutableURLRequest *request = [self.requestSerializer multipartFormRequestWithMethod:@"POST" URLString:[[NSURL URLWithString:path relativeToURL:self.baseURL] absoluteString] parameters:parameters constructingBodyWithBlock:block error:nil];
	
	// Only use parameters in the request entity body (with a content-type of `application/x-www-form-urlencoded`).
	// See RFC 5849, Section 3.4.1.3.1 http://tools.ietf.org/html/rfc5849#section-3.4
	NSMutableDictionary *authorizationParameters = [parameters mutableCopy];
	if (!([method isEqualToString:@"GET"] || [method isEqualToString:@"HEAD"] || [method isEqualToString:@"DELETE"])) {
		if ([[request valueForHTTPHeaderField:@"Content-Type"] hasPrefix:@"application/x-www-form-urlencoded"]) {
			authorizationParameters = parameters;
		}else{
			authorizationParameters = [[self OAuthParameters] mutableCopy];
			if (self.token) {
				authorizationParameters[@"oauth_token"] = self.token;
			}
		}
	}
	
	[request setValue:[self authorizationHeaderForMethod:method path:path parameters:authorizationParameters] forHTTPHeaderField:@"Authorization"];
	[request setHTTPShouldHandleCookies:NO];
	
	return request;
}

#pragma mark - NSCoding

- (id)initWithCoder:(NSCoder *)decoder {
	self = [super init];
	
	if (!self) {
		return nil;
	}
	
	self.consumerKey = [decoder decodeObjectForKey:NSStringFromSelector(@selector(consumerKey))];
	self.consumerSecret = [decoder decodeObjectForKey:NSStringFromSelector(@selector(consumerSecret))];
	self.signatureMethod = (AFOAuthSignatureMethod)[decoder decodeIntegerForKey:NSStringFromSelector(@selector(signatureMethod))];
	self.realm = [decoder decodeObjectForKey:NSStringFromSelector(@selector(realm))];
	self.token = [decoder decodeObjectForKey:NSStringFromSelector(@selector(token))];
	self.tokenSecret = [decoder decodeObjectForKey:NSStringFromSelector(@selector(tokenSecret))];
	self.defaultHeaders = [decoder decodeObjectForKey:@"defaultHeaders"];
	self.parameterEncoding = (AFHTTPClientParameterEncoding) [decoder decodeIntegerForKey:@"parameterEncoding"];
	
	return self;
}

- (void)encodeWithCoder:(NSCoder *)coder {
	[coder encodeObject:self.consumerKey forKey:NSStringFromSelector(@selector(consumerKey))];
	[coder encodeObject:self.consumerSecret forKey:NSStringFromSelector(@selector(consumerSecret))];
	[coder encodeInteger:self.signatureMethod forKey:NSStringFromSelector(@selector(signatureMethod))];
	[coder encodeObject:self.realm forKey:NSStringFromSelector(@selector(realm))];
	[coder encodeObject:self.token forKey:NSStringFromSelector(@selector(token))];
	[coder encodeObject:self.tokenSecret forKey:NSStringFromSelector(@selector(tokenSecret))];
	[coder encodeObject:self.defaultHeaders forKey:@"defaultHeaders"];
	[coder encodeInteger:self.parameterEncoding forKey:@"parameterEncoding"];
}

#pragma mark - NSCopying

- (id)copyWithZone:(NSZone *)zone {
	STLOAuthClient *copy = [[[self class] allocWithZone:zone] initWithBaseURL:self.url consumerKey:self.consumerKey consumerSecret:self.consumerSecret token:self.tokenSecret tokenSecret:self.tokenSecret];
	copy.signatureMethod = self.signatureMethod;
	copy.realm = self.realm;
	copy.token = self.token;
	copy.tokenSecret = self.tokenSecret;
	copy.defaultHeaders = [self.defaultHeaders mutableCopyWithZone:zone];
	copy.parameterEncoding = self.parameterEncoding;
	
	return copy;
}

@end