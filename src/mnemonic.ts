/*
 * 助记词工具类
 */

import { randomBytes } from '@stablelib/random';
import { entropyToMnemonic } from '@ethersproject/hdnode';
import { toUtf8Bytes, UnicodeNormalizationForm } from '@ethersproject/strings';
import { pbkdf2 } from '@ethersproject/pbkdf2';
import { Wordlist } from '@ethersproject/wordlists';
import { hex2bytes } from './hex.js';

/**
 * 随机生成一个助记词
 * @param entropyLength 随机熵的长度
 * @param wordlist 助记词列表
 * @return 助记词
 */
export function randomMnemonic(
  entropyLength: number = 32,
  wordlist?: string | Wordlist,
): string {
  // 随机熵
  const entropy = randomBytes(entropyLength);
  // 根据熵生成助记词
  return entropyToMnemonic(entropy, wordlist);
}

export type Option = {
  password?: string;
  iterations?: number;
  keyLen?: number;
};

/**
 * 助记词转换为秘钥种子
 * @param mnemonic 助记词
 * @param option
 */
export function mnemonicToSeed(
  mnemonic: string,
  option?: {
    /**
     * 密码
     */
    password?: string;
    /**
     * 2024
     */
    iterations?: number;
    /**
     * key 长度
     * 32
     */
    keyLen?: number;
  },
): Uint8Array {
  let { password, iterations = 2048, keyLen = 32 } = option || {};
  if (!password) {
    password = '';
  }

  const salt = toUtf8Bytes(
    'mnemonic' + password,
    UnicodeNormalizationForm.NFKD,
  );

  const seedHexStr = pbkdf2(
    toUtf8Bytes(mnemonic, UnicodeNormalizationForm.NFKD),
    salt,
    iterations,
    keyLen,
    'sha512',
  );
  return hex2bytes(seedHexStr);
}
