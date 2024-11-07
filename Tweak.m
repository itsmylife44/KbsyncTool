#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <objc/runtime.h>
#import <os/log.h>
#import <stdio.h>

#import "pac_helper.h"
#import <Accounts/Accounts.h>
#import <CaptainHook/CaptainHook.h>
#import <Foundation/Foundation.h>
#import <rootless.h>
#import "CrossOverIPC.h"


@interface MicroPaymentQueueRequest : NSObject
@property(retain) NSNumber *userIdentifier;
@property(retain) NSNumber *rangeStartIdentifier;
@property(retain) NSNumber *rangeEndIdentifier;
@property(assign) BOOL needsAuthentication;
- (id)_ntsQueryParameters:(id *)parameters;
- (id)_ntsClientApplication:(id *)application;
- (id)description;
- (id)newStoreURLOperation:(id *)operation;
- (id)init;
@end

@interface SSAccount : NSObject
@property (readonly, nonatomic) ACAccount *backingAccount;
@property (retain, nonatomic) NSObject *backingAccountAccessQueue; // ivar: _backingAccountAccessQueue
@property(copy) NSString *ITunesPassSerialNumber;
@property(copy) NSString *altDSID;
@property(copy) NSString *accountName;
@property(copy) NSString *firstName;
@property(copy) NSString *lastName;
@property(readonly) NSString *localizedName;
@property(copy) NSString *storeFrontIdentifier;
@property(getter=isActive) bool active;
@property(getter=isAuthenticated) bool authenticated;
@property(retain) NSNumber *uniqueIdentifier;
@end

@interface SSAccountStore : NSObject
+ (SSAccountStore *)defaultStore;
@property(readonly) SSAccount *activeAccount;
@end

@interface ISDevice : NSObject
+ (ISDevice *)sharedInstance;
@property(readonly) NSString *guid;
@end

@interface ISStoreURLOperation : NSObject
- (NSURLRequest *)newRequestWithURL:(NSURL *)url;
@end

@interface AMSURLRequest : NSMutableURLRequest
- (AMSURLRequest *)initWithRequest:(NSURLRequest *)urlRequest;
@end

@interface AMSBagNetworkDataSource : NSObject
@end

@interface AMSPromise : NSObject
- (NSDictionary *)resultWithError:(NSError **)errPtr;
@end

@interface AMSAnisette : NSObject
+ (AMSBagNetworkDataSource *)createBagForSubProfile;
+ (AMSPromise *)headersForRequest:(AMSURLRequest *)urlRequest
                          account:(ACAccount *)account
                             type:(long long)type
                              bag:(AMSBagNetworkDataSource *)bagSource;
@end

@interface ACAccountStore (AMS)
+ (ACAccountStore *)ams_sharedAccountStore;
- (ACAccount *)ams_activeiTunesAccount;
@end

@interface SSVFairPlaySubscriptionController : NSObject
- (BOOL)generateSubscriptionBagRequestWithAccountUniqueIdentifier:(unsigned long long)arg1
                                                  transactionType:(unsigned int)arg2
                                                    machineIDData:(NSData *)arg3
                                     returningSubscriptionBagData:(NSData **)arg4
                                                            error:(NSError **)arg5;
@end

@interface PurchaseOperation : NSObject
- (SSVFairPlaySubscriptionController *)_fairPlaySubscriptionController;
@end

@interface AMSMescalSession : NSObject
+ (AMSMescalSession *)sessionWithType:(int)mescalType;
- (NSData *)signData:(NSData *)data bag:(NSDictionary *)bag error:(NSError **)err;
@end

@interface KbsyncTweakHandler : NSObject
+ (instancetype)sharedInstance;
- (NSDictionary *)Callback_handleHeaders:(NSString *)msgName userInfo:(NSDictionary *)userInfo;
- (NSDictionary *)Callback_handleSign:(NSString *)msgName userInfo:(NSDictionary *)userInfoData;
@end


static inline char itoh(int i) {
    if (i > 9)
        return 'A' + (i - 10);
    return '0' + i;
}

static NSString *NSDataToHex(NSData *data) {
    NSUInteger i, len;
    unsigned char *buf, *bytes;

    len = data.length;
    bytes = (unsigned char *)data.bytes;
    buf = (unsigned char *)malloc(len * 2);

    for (i = 0; i < len; i++) {
        buf[i * 2] = itoh((bytes[i] >> 4) & 0xF);
        buf[i * 2 + 1] = itoh(bytes[i] & 0xF);
    }

    return [[NSString alloc] initWithBytesNoCopy:buf length:len * 2 encoding:NSASCIIStringEncoding freeWhenDone:YES];
}

@implementation KbsyncTweakHandler

+ (instancetype)sharedInstance {
    static KbsyncTweakHandler *sharedInstance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        sharedInstance = [[self alloc] init];
    });
    return sharedInstance;
}

- (instancetype)init {
    if (self = [super init]) {
        NSLog(@"KbsyncTweakHandler initialized.");
    }
    return self;
}

- (NSDictionary *)Callback_handleHeaders:(NSString *)msgName userInfo:(NSDictionary *)userInfo {
    NSDictionary *args = userInfo;

    SSAccount *account = [[SSAccountStore defaultStore] activeAccount];
    unsigned long long accountID = [[account uniqueIdentifier] unsignedLongLongValue];

    NSLog(@"Account details: altDSID = %@, uniqueIdentifier = %@", account.altDSID, account.uniqueIdentifier);

    NSLog(@"Got account %@, id %llu", account, accountID);

    NSLog(@"Start to calc kbsync and sbsync, base offset: 0x%lx.", _dyld_get_image_vmaddr_slide(0));

    NSData *kbsync = nil;

    {
        Class KeybagSyncOperationCls = NSClassFromString(@"KeybagSyncOperation");
        NSLog(@"Got KeybagSyncOperation class: %p.", KeybagSyncOperationCls);

        Method RunMethod = class_getInstanceMethod(KeybagSyncOperationCls, NSSelectorFromString(@"run"));
        NSLog(@"Got -run method: %p.", RunMethod);

        IMP RunIMP = method_getImplementation(RunMethod);
        NSLog(@"Got -run implementation: %p.", RunIMP);

        #if __arm64e__
        const uint32_t *kbsync_caller = (uint32_t *)make_sym_readable((void *)RunIMP);
        #else
        const uint32_t *kbsync_caller = (uint32_t *)RunIMP;
        #endif

        const uint8_t mov_w1_0xb[] = {
            0x61, 0x01, 0x80, 0x52,
        };
        while (*kbsync_caller++ != *(uint32_t *)&mov_w1_0xb[0])
            ;
        NSLog(@"Parsed kbsync caller: %p.", kbsync_caller);

        int blopcode, blmask;
        blopcode = *(int *)kbsync_caller;
        blmask = 0xFC000000;
        if (blopcode & (1 << 26)) {
            blopcode |= blmask; // sign extend
        } else {
            blopcode &= ~blmask;
        }

        long kbsync_entry = (long)kbsync_caller + (blopcode << 2);
        NSLog(@"Decoded kbsync entry: 0x%lx.", kbsync_entry);

        #if __arm64e__
        kbsync_entry = (long)make_sym_callable((void *)kbsync_entry);
        #endif

        kbsync = (__bridge NSData *)((CFDataRef(*)(long, int))kbsync_entry)(accountID, 0xB);
        NSLog(@"Got kbsync: %@", [kbsync base64EncodedStringWithOptions:kNilOptions]);
    }

    NSData *sbsync = nil;

    do {
        Class PurchaseOperationCls = NSClassFromString(@"PurchaseOperation");
        NSLog(@"Got PurchaseOperation class: %p.", PurchaseOperationCls);

        Method FairMethod = class_getInstanceMethod(PurchaseOperationCls, NSSelectorFromString(@"_addFairPlayToRequestProperties:withAccountIdentifier:"));
        NSLog(@"Got -_addFairPlayToRequestProperties:withAccountIdentifier: method: %p.", FairMethod);

        IMP FairIMP = method_getImplementation(FairMethod);
        NSLog(@"Got -_addFairPlayToRequestProperties:withAccountIdentifier: implementation: %p.", FairIMP);

        #if __arm64e__
        const uint32_t *machine_id_caller = (uint32_t *)make_sym_readable((void *)FairIMP);
        #else
        const uint32_t *machine_id_caller = (uint32_t *)FairIMP;
        #endif

        const uint8_t movn_x0_0x0[] = {
            0x00, 0x00, 0x80, 0x92,
        };
        CFDataRef machine_id = NULL;
        while (*machine_id_caller++ != *(uint32_t *)&movn_x0_0x0[0])
            ;
        NSLog(@"Parsed machine_id caller: %p.", machine_id_caller);

        int blopcode, blmask;
        blopcode = *(int *)machine_id_caller;
        blmask = 0xFC000000;
        if (blopcode & (1 << 26)) {
            blopcode |= blmask;
            blopcode ^= blmask; // sign extend
        } else {
            blopcode &= ~blmask;
        }

        long machine_id_entry = (long)machine_id_caller + (blopcode << 2);
        NSLog(@"Decoded machine_id entry: 0x%lx.", machine_id_entry);

        #if __arm64e__
        machine_id_entry = (long)make_sym_callable((void *)machine_id_entry);
        #endif

        char *md_str = NULL;
        size_t md_len = 0;
        char *amd_str = NULL;
        size_t amd_len = 0;
        int md_ret = ((int (*)(long, char **, size_t *, char **, size_t *))machine_id_entry)(
            0xffffffffffffffff, &md_str, &md_len, &amd_str, &amd_len);
        if (md_ret) {
            break;
        }

        NSData *mdData = [[NSData alloc] initWithBytesNoCopy:md_str length:md_len freeWhenDone:NO];
        NSLog(@"Got Machine ID data: %@", [mdData base64EncodedStringWithOptions:kNilOptions]);

        NSData *amdData = [[NSData alloc] initWithBytesNoCopy:amd_str length:amd_len freeWhenDone:NO];
        NSLog(@"Got Apple Machine ID data: %@", [amdData base64EncodedStringWithOptions:kNilOptions]);

        NSError *sbsyncErr = nil;
        PurchaseOperation *purchaseOp = [[NSClassFromString(@"PurchaseOperation") alloc] init];
        SSVFairPlaySubscriptionController *fairPlayCtrl = [purchaseOp _fairPlaySubscriptionController];
        BOOL sbsyncSucceed = [fairPlayCtrl generateSubscriptionBagRequestWithAccountUniqueIdentifier:accountID
                                                                                      transactionType:0x138
                                                                                        machineIDData:mdData
                                                                             returningSubscriptionBagData:&sbsync
                                                                                                error:&sbsyncErr];
        if (!sbsyncSucceed) {
            NSLog(@"Failed to generate subscription bag request: %@", sbsyncErr);
            break;
        }

        NSLog(@"Got sbsync: %@", [sbsync base64EncodedStringWithOptions:kNilOptions]);
    } while (0);

    NSMutableDictionary *returnDict = [NSMutableDictionary dictionary];
    dispatch_sync((dispatch_queue_t)account.backingAccountAccessQueue, ^{
        returnDict[@"backingIdentifier"] = [[account backingAccount] identifier];
    });

    if ([account ITunesPassSerialNumber]) {
        returnDict[@"iTunesPassSerialNumber"] = [account ITunesPassSerialNumber];
    }
    if ([account altDSID]) {
        returnDict[@"altDSID"] = [account altDSID];
    }
    if ([account accountName]) {
        returnDict[@"accountName"] = [account accountName];
    }
    if ([account firstName]) {
        returnDict[@"firstName"] = [account firstName];
    }
    if ([account lastName]) {
        returnDict[@"lastName"] = [account lastName];
    }
    if ([account localizedName]) {
        returnDict[@"localizedName"] = [account localizedName];
    }
    if ([account storeFrontIdentifier]) {
        returnDict[@"storeFrontIdentifier"] = [account storeFrontIdentifier];
    }

    returnDict[@"active"] = @([account isActive]);
    returnDict[@"authenticated"] = @([account isAuthenticated]);
    returnDict[@"uniqueIdentifier"] = @(accountID);
    returnDict[@"guid"] = [[NSClassFromString(@"ISDevice") sharedInstance] guid];

    NSURL *url = [NSURL URLWithString:args[@"url"]];
    NSLog(@"URL for request: %@", url);
    ISStoreURLOperation *operation = [[NSClassFromString(@"ISStoreURLOperation") alloc] init];
    NSURLRequest *urlRequest = [operation newRequestWithURL:url];
    AMSURLRequest *amsRequest = [[NSClassFromString(@"AMSURLRequest") alloc] initWithRequest:urlRequest];
    NSMutableDictionary *headerFields = [[urlRequest allHTTPHeaderFields] mutableCopy];
    NSLog(@"Headers for AMS request: %@", headerFields);


    ACAccount *amsAccount = [[ACAccountStore ams_sharedAccountStore] ams_activeiTunesAccount];
    NSLog(@"AMS Account details: username = %@, identifier = %@", amsAccount.username, amsAccount.identifier);

    AMSBagNetworkDataSource *bagSource = [NSClassFromString(@"AMSAnisette") createBagForSubProfile];
    NSDictionary *amsHeader1 = [[NSClassFromString(@"AMSAnisette") headersForRequest:amsRequest
                                                                             account:amsAccount
                                                                                type:1
                                                                                 bag:bagSource] resultWithError:nil];
    if ([amsHeader1 isKindOfClass:[NSDictionary class]]) {
        [headerFields addEntriesFromDictionary:amsHeader1];
    }

    NSDictionary *amsHeader2 = [[NSClassFromString(@"AMSAnisette") headersForRequest:amsRequest
                                                                             account:amsAccount
                                                                                type:2
                                                                                 bag:bagSource] resultWithError:nil];
    if ([amsHeader2 isKindOfClass:[NSDictionary class]]) {
        [headerFields addEntriesFromDictionary:amsHeader2];
    }

    [headerFields removeObjectForKey:@"Authorization"];
    returnDict[@"headers"] = headerFields;

    NSString *kbsyncString = nil;
    if ([args[@"kbsyncType"] isEqualToString:@"hex"]) {
        kbsyncString = NSDataToHex(kbsync);
    } else {
        kbsyncString = [kbsync base64EncodedStringWithOptions:kNilOptions];
    }
    returnDict[@"kbsync"] = kbsyncString;

    NSString *sbsyncString = nil;
    if ([args[@"sbsyncType"] isEqualToString:@"hex"]) {
        sbsyncString = NSDataToHex(sbsync);
    } else {
        sbsyncString = [sbsync base64EncodedStringWithOptions:kNilOptions];
    }
    returnDict[@"sbsync"] = sbsyncString;

    return returnDict;
}

- (NSDictionary *)Callback_handleSign:(NSString *)msgName userInfo:(NSDictionary *)userInfoData {
    NSDictionary *userInfo = [NSPropertyListSerialization propertyListWithData:(NSData *)userInfoData
                                                                       options:kNilOptions
                                                                        format:nil
                                                                         error:nil];

    NSData *signbody = userInfo[@"body"];
    NSNumber *mescalType = userInfo[@"mescalType"]; // 1 or 2
    NSDictionary *bagDict = userInfo[@"bag"]; // 1 or 2

    NSMutableDictionary *returnDict = [NSMutableDictionary dictionary];

    NSLog(@"Start to calc signSap...");

    AMSMescalSession *session = [NSClassFromString(@"AMSMescalSession") sessionWithType:[mescalType intValue]];

    NSError *retError = nil;
    NSData *signature = [session signData:signbody bag:bagDict error:&retError];

    if (retError != nil) {
        NSLog(@"kbsync_result_callback cannot call [AMSMescalSession signData]: %@", retError);
        return nil;
    }

    NSString *signatureString = NSDataToHex(signature);

    returnDict[@"signature"] = signatureString;

    return returnDict;
}

@end

CHConstructor {

    if ([[[NSProcessInfo processInfo] processName] isEqualToString:@"itunesstored"]) {

        static CFMessagePortRef localPort = nil;
        static dispatch_once_t onceToken;

        dispatch_once(&onceToken, ^{
          void *sandyHandle = dlopen(ROOT_PATH("/usr/lib/libsandy.dylib"), RTLD_LAZY);
          if (sandyHandle) {
              os_log_info(OS_LOG_DEFAULT, "libSandy loaded");
              int (*__dyn_libSandy_applyProfile)(const char *profileName) =
                  (int (*)(const char *))dlsym(sandyHandle, "libSandy_applyProfile");
              if (__dyn_libSandy_applyProfile) {
                  __dyn_libSandy_applyProfile("KbsyncTool");
              }
          }
        });

        CrossOverIPC *crossOverIPC = [objc_getClass("CrossOverIPC") centerNamed:@"com.darwindev.kbsync.port" type:SERVICE_TYPE_LISTENER];
        if (crossOverIPC) {

            KbsyncTweakHandler *handler = [KbsyncTweakHandler sharedInstance];

            [crossOverIPC registerForMessageName:@"kbsync" target:handler selector:@selector(Callback_handleHeaders:userInfo:)];
            [crossOverIPC registerForMessageName:@"kbsync_signature" target:handler selector:@selector(Callback_handleSign:userInfo:)];

            NSLog(@"kbsync & kbsync_signature handlers registered.");
        } else {
            NSLog(@"Failed to initialize CrossOverIPC listener.");
        }

    }
}

