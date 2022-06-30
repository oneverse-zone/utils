import * as u8a from 'uint8arrays';

/**
 * 十六进制字符串转换为 Uint8Array
 * @param s 16进制字符串
 */
export function hex2bytes(s: string): Uint8Array {
  const input = s.startsWith('0x') ? s.substring(2) : s;
  return u8a.fromString(input.toLowerCase(), 'base16');
}
