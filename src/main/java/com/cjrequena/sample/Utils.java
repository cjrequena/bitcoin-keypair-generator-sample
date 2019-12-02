package com.cjrequena.sample;

/**
 * <p>
 * <p>
 * <p>
 * <p>
 * @author cjrequena
 *
 */
public class Utils {

  /**
   *
   * @param hex
   * @return
   */
  public static String adjustTo64(String hex) {
    switch (hex.length()) {
      case 62:
        return "00" + hex;
      case 63:
        return "0" + hex;
      case 64:
        return hex;
      default:
        throw new IllegalArgumentException("not a valid key: " + hex);
    }
  }

  /**
   *
   * @param bytes
   * @return
   */
  public static String bytesToHex(byte[] bytes) {
    StringBuilder sb = new StringBuilder();
    for (byte b : bytes) {
      sb.append(String.format("%02x", b));
    }
    return sb.toString();
  }

  /**
   *
   * @param hex
   * @return
   */
  public static byte[] hexToBytes(String hex) {
    int len = hex.length();
    byte[] data = new byte[len / 2];
    for (int i = 0; i < len; i += 2) {
      data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
        + Character.digit(hex.charAt(i + 1), 16));
    }
    return data;
  }
}
