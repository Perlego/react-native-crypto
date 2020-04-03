#import <React/RCTBridgeModule.h>

@interface Crypto : NSObject <RCTBridgeModule>
+ (NSString *) encrypt: (NSString *)clearText  key: (NSString *)key iv: (NSString *)iv;
+ (NSString *) decrypt: (NSString *)cipherText key: (NSString *)key iv: (NSString *)iv;
@end
