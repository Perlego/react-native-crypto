#import "Crypto.h"

@implementation Crypto

+ (NSData *) AES256CBC: (NSString *)operation data: (NSData *)data key: (NSString *)key iv: (NSString *)iv {
    NSData *keyData = [key dataUsingEncoding:NSUTF8StringEncoding];
    NSData *ivData = [self fromHex:iv];
    size_t numBytes = 0;

    NSMutableData * buffer = [[NSMutableData alloc] initWithLength:[data length] + kCCBlockSizeAES128];

    CCCryptorStatus cryptStatus = CCCrypt(
                                          [operation isEqualToString:@"encrypt"] ? kCCEncrypt : kCCDecrypt,
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

+ (NSString *) encrypt: (NSString *)clearText key: (NSString *)key iv: (NSString *)iv {
   NSData *result = [self AES128CBC:@"encrypt" data:[clearText dataUsingEncoding:NSUTF8StringEncoding] key:key iv:iv];
   return [result base64EncodedStringWithOptions:0];
}

+ (NSString *) decrypt: (NSString *)cipherText key: (NSString *)key iv: (NSString *)iv isImage: (BOOL)isImage {
   NSData *textData = [self fromHex:cipherText];
   NSData *result = [self AES128CBC:@"decrypt" data:textData key:key iv:iv];
   if (isImage) {
       return [result base64EncodedStringWithOptions:0];
   }
   return [[NSString alloc] initWithData:result encoding:NSUTF8StringEncoding];
}

RCT_EXPORT_MODULE()

RCT_EXPORT_METHOD(encrypt:(NSString *)data key:(NSString *)key iv:(NSString *)iv
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    NSError *error = nil;
    NSString *base64 = [AesCrypt encrypt:data key:key iv:iv];
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
    NSString *data = [AesCrypt decrypt:base64 key:key iv:iv isImage:isImage];
    if (data == nil) {
        reject(@"decrypt_fail", @"Decrypt failed", error);
    } else {
        resolve(data);
    }
}

@end
