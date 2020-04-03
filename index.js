import { NativeModules } from 'react-native';

const { Crypto } = NativeModules;

export const encryptAES = (clearText, key, iv) => {
  return Crypto.encrypt(clearText, key, iv);
};

export const decryptAES = (cipherText, key, iv) => {
  return Crypto.decrypt(cipherText, key, iv);
};
