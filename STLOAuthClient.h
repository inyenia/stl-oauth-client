//
//  AFOAuth1Client.h
//
//  Created by Joel Chen on 3/4/14.
//  Copyright (c) 2014 Joel Chen [http://lnkd.in/bwwnBWR]
//

#import <Foundation/Foundation.h>
#import "AFNetworking.h"

typedef NS_ENUM(NSUInteger, AFOAuthSignatureMethod) {
	AFPlainTextSignatureMethod = 1,
	AFHMACSHA1SignatureMethod = 2,
};

typedef enum {
	AFFormURLParameterEncoding,
	AFJSONParameterEncoding,
	AFPropertyListParameterEncoding,
} AFHTTPClientParameterEncoding;

typedef void (^AFServiceProviderRequestHandlerBlock)(NSURLRequest *request);
typedef void (^AFServiceProviderRequestCompletionBlock)();

@class STLOAuthClient;

@interface STLOAuthClient : AFHTTPRequestOperationManager
@property (readwrite, nonatomic, copy) NSURL *url;
@property (readwrite, nonatomic, copy) NSString *consumerKey;
@property (readwrite, nonatomic, copy) NSString *consumerSecret;
@property (readwrite, nonatomic, copy) NSString *token;
@property (readwrite, nonatomic, copy) NSString *tokenSecret;
@property (readwrite, nonatomic, strong) id applicationLaunchNotificationObserver;
@property (readwrite, nonatomic, copy) AFServiceProviderRequestHandlerBlock serviceProviderRequestHandler;
@property (readwrite, nonatomic, copy) AFServiceProviderRequestCompletionBlock serviceProviderRequestCompletion;
///-----------------------------------
/// @name Managing OAuth Configuration
///-----------------------------------

@property (nonatomic, assign) AFOAuthSignatureMethod signatureMethod;

@property (nonatomic, copy) NSString *realm;

@property (nonatomic, strong) NSMutableDictionary *defaultHeaders;

@property (nonatomic, assign) AFHTTPClientParameterEncoding parameterEncoding;

@property (nonatomic, assign) NSStringEncoding stringEncoding;

+ (NSString *)queryStringFromParameters:(NSDictionary *)parameters encoding:(NSStringEncoding)stringEncoding;

- (NSMutableURLRequest *)requestWithMethod:(NSString *)method path:(NSString *)path parameters:(NSDictionary *)parameters;
- (NSMutableURLRequest *)multipartFormRequestWithMethod:(NSString *)method
												   path:(NSString *)path
											 parameters:(NSDictionary *)parameters
							  constructingBodyWithBlock:(void (^)(id <AFMultipartFormData> formData))block;

///---------------------
/// @name Initialization
///---------------------

/**
 
 */
- (id)initWithBaseURL:(NSURL *)url
		  consumerKey:(NSString *)consumerKey
	   consumerSecret:(NSString *)consumerSecret
				token:(NSString *)token
		  tokenSecret:(NSString *)tokenSecret;

///----------------------------------------------------
/// @name Configuring Service Provider Request Handling
///----------------------------------------------------

/**
 
 */
- (void)setServiceProviderRequestHandler:(void (^)(NSURLRequest *request))block
							  completion:(void (^)())completion;
@end

///----------------
/// @name Constants
///----------------

/**
 
 */
extern NSString * const kAFApplicationLaunchedWithURLNotification;

/**
 
 */
extern NSString * const kAFApplicationLaunchOptionsURLKey;

