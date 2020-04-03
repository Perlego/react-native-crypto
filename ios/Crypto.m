#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonKeyDerivation.h>

#import "Crypto.h"

@implementation Crypto

+ (NSData *) AES256CBC: (CCOperation)operation data: (NSData *)data key: (NSString *)key iv: (NSString *)iv {
    NSData *keyData = [key dataUsingEncoding:NSUTF8StringEncoding];
    NSData *ivData = [iv dataUsingEncoding:NSUTF8StringEncoding];
    size_t numBytes = 0;

    NSMutableData * buffer = [[NSMutableData alloc] initWithLength:[data length] + kCCBlockSizeAES128];

    CCCryptorStatus cryptStatus = CCCrypt(operation,
                                          kCCAlgorithmAES128,
                                          kCCOptionPKCS7Padding,
                                          keyData.bytes, kCCKeySizeAES256,
                                          ivData.bytes,
                                          data.bytes, data.length,
                                          buffer.mutableBytes,  buffer.length,
                                          &numBytes);

    if (cryptStatus == kCCSuccess) {
        [buffer setLength:numBytes];
        return buffer;
    }
    return nil;
}

//+ (NSString *) encrypt: (NSString *)clearText key: (NSString *)key iv: (NSString *)iv {
//
//}
//
//+ (NSString *) decrypt: (NSString *)cipherText key: (NSString *)key iv: (NSString *)iv isImage: (BOOL)isImage {
//  
//}

RCT_EXPORT_MODULE()

RCT_EXPORT_METHOD(encrypt:(NSString *)data key:(NSString *)key iv:(NSString *)iv
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    NSError *error = nil;
    NSData *textData = [data dataUsingEncoding:NSUTF8StringEncoding];
    NSData *result = [Crypto AES256CBC:kCCEncrypt data:textData key:key iv:iv];
    NSString *base64 = [result base64EncodedStringWithOptions:0];
    if (base64 == nil) {
        reject(@"encrypt_fail", @"Encrypt error", error);
    } else {
        resolve(base64);
    }
}

RCT_EXPORT_METHOD(decrypt:(NSString *)base64 key:(NSString *)key iv:(NSString *)iv
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    NSError *error = nil;
    NSData *textData = [base64 dataUsingEncoding:NSUTF8StringEncoding];
    NSData *result = [Crypto AES256CBC:kCCDecrypt data:textData key:key iv:iv];
    NSString *data = [[NSString alloc] initWithData:result encoding:NSUTF8StringEncoding];

    if (data == nil) {
        reject(@"decrypt_fail", @"Decrypt failed", error);
    } else {
        resolve(data);
    }
}

@end
