import { NativeModules } from 'react-native';

const { Crypto } = NativeModules;

export const encryptAES256CBC = (clearText, key, iv) => {
  return Crypto.encryptAES256CBC(clearText, key, iv);
};

export const decryptAES256CBC = (cipherText, key, iv) => {
  return Crypto.decryptAES256CBC(cipherText, key, iv);
};

export const encodeBase64 = () => {
  return Crypto.encodeBase64();
};

export const decodeBase64 = () => {
  return Crypto.decodeBase64();
};