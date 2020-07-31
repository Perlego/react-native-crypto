#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonKeyDerivation.h>

#import "Crypto.h"

@implementation Crypto

+ (NSData *) fromHex: (NSString *)string {
    NSMutableData *data = [[NSMutableData alloc] init];
    unsigned char whole_byte;
    char byte_chars[3] = {'\0','\0','\0'};
    for (int i = 0; i < ([string length] / 2); i++) {
        byte_chars[0] = [string characterAtIndex:i*2];
        byte_chars[1] = [string characterAtIndex:i*2+1];
        whole_byte = strtol(byte_chars, NULL, 16);
        [data appendBytes:&whole_byte length:1];
    }
    return data;
}

+ (NSData *) AES256CBC: (CCOperation)operation data: (NSData *)data key: (NSString *)key iv: (NSString *)iv {
    NSData *keyData = [key dataUsingEncoding:NSUTF8StringEncoding];
    NSData *ivData = [self fromHex:iv];
    size_t numBytes = 0;

    NSMutableData * buffer = [[NSMutableData alloc] initWithLength:[data length] + kCCBlockSizeAES128];

    CCCryptorStatus cryptStatus = CCCrypt(operation,
                                          kCCAlgorithmAES128,
                                          kCCOptionPKCS7Padding,
                                          keyData.bytes, kCCKeySizeAES256,
                                          ivData.bytes,
                                          data.bytes, data.length,
                                          buffer.mutableBytes, buffer.length,
                                          &numBytes);

    if (cryptStatus == kCCSuccess) {
        [buffer setLength:numBytes];
        return buffer;
    }
    return nil;
}

RCT_EXPORT_MODULE()

RCT_EXPORT_METHOD(encryptAES256CBC:(NSString *)data key:(NSString *)key iv:(NSString *)iv
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    NSData *textData = [data dataUsingEncoding:NSUTF8StringEncoding];
    NSData *result = [Crypto AES256CBC:kCCEncrypt data:textData key:key iv:iv];
    NSString *base64 = [result base64EncodedStringWithOptions:0];
    
    if (base64 == nil) {
        reject(@"encrypt_fail", @"Encrypt error", nil);
    } else {
        resolve(base64);
    }
}

RCT_EXPORT_METHOD(decryptAES256CBC:(NSString *)cipherText key:(NSString *)key iv:(NSString *)iv base64:(BOOL)base64
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    NSData *textData = [Crypto fromHex:cipherText];
    NSData *result = [Crypto AES256CBC:kCCDecrypt data:textData key:key iv:iv];
    NSString *data =[[NSString alloc] initWithData:result encoding:NSUTF8StringEncoding];

    if (base64) {
        NSData *decodedData = [[NSData alloc] initWithBase64EncodedString:data options:0];
        data = [[NSString alloc] initWithData:decodedData encoding:NSUTF8StringEncoding];
    }

    if (data == nil) {
        reject(@"decrypt_fail", @"Decrypt failed", nil);
    } else {
        resolve(data);
    }
}

RCT_EXPORT_METHOD(encodeBase64:(NSString *)text
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    NSData *plainData = [text dataUsingEncoding:NSUTF8StringEncoding];
    NSString *base64String = [plainData base64EncodedStringWithOptions:0];
    resolve(base64String);
}

RCT_EXPORT_METHOD(decodeBase64:(NSString *)base64
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    NSData *decodedData = [[NSData alloc] initWithBase64EncodedString:base64 options:0];
    NSString *decodedString = [[NSString alloc] initWithData:decodedData encoding:NSUTF8StringEncoding];
    resolve(decodedString);
}

@end
