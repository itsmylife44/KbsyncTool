#import <Foundation/Foundation.h>
#import <stdio.h>
#import "GCDWebServer.h"
#import "GCDWebServerDataResponse.h"
#import "GCDWebServerErrorResponse.h"
#import "CrossOverIPC.h"

#pragma mark - Helper Functions

static NSData *createJSONData(id object, NSError **error) {
    if (![NSJSONSerialization isValidJSONObject:object]) {
        if (error) {
            *error = [NSError errorWithDomain:@"com.server.error"
                                         code:400
                                     userInfo:@{NSLocalizedDescriptionKey: @"Invalid JSON object"}];
        }
        return nil;
    }
    return [NSJSONSerialization dataWithJSONObject:object options:(NSJSONWritingPrettyPrinted | NSJSONWritingSortedKeys) error:error];
}

static NSDictionary *generateErrorResponse(NSString *message) {
    return @{@"error": message ?: @"Unknown error"};
}

static void logError(NSString *message) {
    fprintf(stderr, "%s\n", [message UTF8String]);
}

static CrossOverIPC *getCrossOverIPC() {
    CrossOverIPC *crossOver = [objc_getClass("CrossOverIPC") centerNamed:@"com.darwindev.kbsync.port" type:SERVICE_TYPE_SENDER];
    if (!crossOver) {
        logError(@"No remote service found");
    }
    return crossOver;
}

#pragma mark - CrossOver IPC Handlers

static id handleKBSyncRequest(NSString *urlString, NSString *syncType) {
    CrossOverIPC *crossOver = getCrossOverIPC();
    if (!crossOver) return generateErrorResponse(@"Failed to initialize CrossOverIPC");

    NSDictionary *response = [crossOver sendMessageAndReceiveReplyName:@"kbsync" userInfo:@{
        @"url": urlString,
        @"kbsyncType": syncType,
        @"sbsyncType": syncType
    }];

    if (!response) {
        logError(@"Failed to receive response from kbsync");
        return generateErrorResponse(@"Failed to receive response from kbsync");
    }
    return response;
}

static id handleSignatureRequest(NSData *signBody, NSNumber *mescalType, NSDictionary *bag) {
    CrossOverIPC *crossOver = getCrossOverIPC();
    if (!crossOver) return generateErrorResponse(@"Failed to initialize CrossOverIPC");

    NSDictionary *response = [crossOver sendMessageAndReceiveReplyName:@"kbsync_signature" userInfo:@{
        @"body": signBody,
        @"mescalType": mescalType,
        @"bag": bag
    }];

    if (!response) {
        logError(@"Failed to receive response from kbsync_signature");
        return generateErrorResponse(@"Failed to receive response from kbsync_signature");
    }
    return response;
}

#pragma mark - Main Logic

int main(int argc, char *argv[]) {
    @autoreleasepool {
        if (argc != 2 && argc != 3) {
            fprintf(stderr, "Usage: %s [url] [-p port]\n", argv[0]);
            return 1;
        }

        if (argc == 2) {
            // Handle single request
            NSString *urlString = [NSString stringWithUTF8String:argv[1]];
            id response = handleKBSyncRequest(urlString, @"base64");

            NSError *error = nil;
            NSData *jsonData = createJSONData(response, &error);
            if (!jsonData) {
                logError(@"Failed to serialize JSON");
                return 1;
            }

            NSString *jsonString = [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
            printf("%s\n", [jsonString UTF8String]);
            return 0;

        } else {
            // Launch HTTP server
            NSInteger port = [[NSString stringWithUTF8String:argv[2]] integerValue];
            if (port <= 0 || port > 65535) {
                logError(@"Invalid port number");
                return 1;
            }

            GCDWebServer *webServer = [[GCDWebServer alloc] init];

            // Web server callback handler
            GCDWebServerAsyncProcessBlock processRequest = ^(GCDWebServerRequest *request, GCDWebServerCompletionBlock completionBlock) {
                id returnObj = nil;

                if ([[[request URL] path] isEqualToString:@"/sign"]) {
                    // Handle /sign request
                    NSString *bodyString = [request query][@"body"];
                    NSData *body = [[NSData alloc] initWithBase64EncodedString:bodyString options:0];
                    NSString *mescalTypeString = [request query][@"mescalType"];
                    NSNumber *mescalType = @([mescalTypeString intValue]);

                    NSString *bagJsonString = [request query][@"bagJson"];
                    NSData *bagJsonData = [bagJsonString dataUsingEncoding:NSUTF8StringEncoding];
                    NSError *error = nil;
                    NSDictionary *bag = [NSJSONSerialization JSONObjectWithData:bagJsonData options:0 error:&error];

                    if (!bag) {
                        completionBlock([GCDWebServerErrorResponse responseWithClientError:kGCDWebServerHTTPStatusCode_BadRequest message:@"Invalid bag JSON"]);
                        return;
                    }

                    returnObj = handleSignatureRequest(body, mescalType, bag);

                } else {
                    // Handle other requests
                    NSString *urlString = [request query][@"url"];
                    if (!urlString) {
                        completionBlock([GCDWebServerErrorResponse responseWithClientError:kGCDWebServerHTTPStatusCode_BadRequest message:@"Missing URL"]);
                        return;
                    }

                    returnObj = handleKBSyncRequest(urlString, @"hex");
                }

                NSError *error = nil;
                NSData *jsonData = createJSONData(returnObj, &error);
                if (!jsonData) {
                    completionBlock([GCDWebServerErrorResponse responseWithServerError:kGCDWebServerHTTPStatusCode_InternalServerError message:@"Failed to serialize JSON"]);
                    return;
                }

                completionBlock([GCDWebServerDataResponse responseWithData:jsonData contentType:@"application/json"]);
            };

            // Add server handlers for GET and POST requests
            [webServer addDefaultHandlerForMethod:@"GET" requestClass:[GCDWebServerRequest class] asyncProcessBlock:processRequest];
            [webServer addDefaultHandlerForMethod:@"POST" requestClass:[GCDWebServerRequest class] asyncProcessBlock:processRequest];

            // Start the server
            [webServer startWithPort:port bonjourName:nil];
            NSLog(@"Server started at: http://localhost:%ld", (long)port);

            // Keep the server running
            CFRunLoopRun();
            return 0;
        }
    }
}
