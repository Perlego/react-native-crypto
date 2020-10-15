#import <React/RCTBridgeModule.h>

@interface Crypto : NSObject <RCTBridgeModule>
+ (NSData *) fromHex: (NSString *)string;
+ (NSData *) AES256CBC: (CCOperation)operation data: (NSData *)data key: (NSString *)key iv: (NSString *)iv;
+ (NSString *)decryptString:(NSString *)str privateKey:(NSString *)privKey;
+ (NSData *)decryptData:(NSData *)data privateKey:(NSString *)privKey;
@end
