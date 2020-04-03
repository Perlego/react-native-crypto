#import <React/RCTBridgeModule.h>

@interface Crypto : NSObject <RCTBridgeModule>
+ (NSData *) AES256CBC: (CCOperation)operation data: (NSData *)data key: (NSString *)key iv: (NSString *)iv;
@end
