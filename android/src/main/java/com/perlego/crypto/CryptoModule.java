package com.perlego.crypto;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

import org.spongycastle.util.encoders.Hex;

import android.util.Base64;

import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.Callback;

public class CryptoModule extends ReactContextBaseJavaModule {

    private final ReactApplicationContext reactContext;

    private static final String CIPHER_ALGORITHM = "AES_256/CBC/PKCS7Padding";
    private static final String KEY_ALGORITHM = "AES_256";

    public CryptoModule(ReactApplicationContext reactContext) {
        super(reactContext);
        this.reactContext = reactContext;
    }

    @Override
    public String getName() {
        return "Crypto";
    }

    @ReactMethod
    public void encryptAES256CBC(String text, String key, String iv, Promise promise) {
        try {
            IvParameterSpec ivSpec = new IvParameterSpec(Hex.decode(iv));
            SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), KEY_ALGORITHM);

            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
            byte[] encrypted = cipher.doFinal(text.getBytes());
            String base64 = Base64.encodeToString(encrypted, Base64.NO_WRAP);
            promise.resolve(base64);
        } catch (Exception e) {
            promise.reject("-1", e.getMessage());
        }
    }

    @ReactMethod
    public void decryptAES256CBC(String cipherText, String key, String iv, Promise promise) {
        try {
            IvParameterSpec ivSpec = new IvParameterSpec(Hex.decode(iv));
            SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), KEY_ALGORITHM);

            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
            byte[] decrypted = cipher.doFinal(Base64.decode(cipherText, Base64.NO_WRAP));
            promise.resolve(new String(decrypted));
        } catch (Exception e) {
            promise.reject("-1", e.getMessage());
        }
    }

    @ReactMethod
    public void encodeBase64(String text, Promise promise) {
        promise.resolve(Base64.encodeToString(text.getBytes(), Base64.NO_WRAP));
    }

    @ReactMethod
    public void decodeBase64(String base64, Promise promise) {
        byte[] data = Base64.decode(base64, Base64.NO_WRAP);
        promise.resolve(new String(data));
    }
}
