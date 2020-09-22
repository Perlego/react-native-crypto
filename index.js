import { NativeModules } from 'react-native';

const { Crypto, RSA } = NativeModules;

export const encryptAES256CBC = (clearText, key, iv) => {
  return Crypto.encryptAES256CBC(clearText, key, iv);
};

export const decryptAES256CBC = (cipherText, key, iv, base64) => {
  return Crypto.decryptAES256CBC(cipherText, key, iv, base64);
};

export const encryptRSA = (str, pubKey) => {
  return RSA.encryptRSA(str, pubKey);
};

export const decryptRSA = (str, privateKey) => {
  return RSA.decryptRSA(str, privateKey);
};

export const encodeBase64 = (text) => {
  return Crypto.encodeBase64(text);
};

export const decodeBase64 = (base64) => {
  return Crypto.decodeBase64(base64);
};