#import <Foundation/Foundation.h>
typedef enum {
    KeyTypePublic = 0,
    KeyTypePrivate
}KeyType;

@interface RSAHandler : NSObject

- (BOOL)importKeyWithType:(KeyType)type andPath:(NSString*)path;
- (BOOL)importKeyWithType:(KeyType)type andkeyString:(NSString *)keyString;

//私钥验证签名 Sha1 + RSA
- (BOOL)verifyString:(NSString *)string withSign:(NSString *)signString;
//验证签名 md5 + RSA
- (BOOL)verifyMD5String:(NSString *)string withSign:(NSString *)signString;

//私钥签名
- (NSString *)signString:(NSString *)string;
- (NSString *)signMD5String:(NSString *)string;

//公钥加密
- (NSString *)encryptWithPublicKey:(NSString*)content;
//私钥解密
- (NSString *)decryptWithPrivatecKey:(NSString*)content;
//公钥解密
- (NSData *)decryptWithPublicKey:(NSData*)data;
@end
