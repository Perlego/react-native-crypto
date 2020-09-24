#import <React/RCTBridgeModule.h>

@interface RSA : NSObject <RCTBridgeModule>

+ (NSString *)decryptString:(NSString *)str privateKey:(NSString *)privKey;
+ (NSData *)decryptData:(NSData *)data privateKey:(NSString *)privKey;

@end