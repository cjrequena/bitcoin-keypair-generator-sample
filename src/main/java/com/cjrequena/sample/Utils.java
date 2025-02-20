package com.cjrequena.sample;

/**
 * Utility class providing methods for hex string manipulation and conversion.
 *
 * <p>This class contains methods to adjust hex strings to a fixed length of 64 characters,
 * convert byte arrays to hex strings, and convert hex strings back to byte arrays.</p>
 *
 * @author cjrequena
 */
public class Utils {

  /**
   * Adjusts a given hex string to a length of 64 characters by adding leading zeros if necessary.
   *
   * @param hex the input hex string
   * @return a 64-character hex string with leading zeros if required
   * @throws IllegalArgumentException if the input string is not a valid length
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
        throw new IllegalArgumentException("Not a valid key: " + hex);
    }
  }

  /**
   * Converts a byte array to a hex string.
   *
   * @param bytes the byte array to convert
   * @return a string representing the hexadecimal value of the byte array
   */
  public static String bytesToHex(byte[] bytes) {
    StringBuilder sb = new StringBuilder();
    for (byte b : bytes) {
      sb.append(String.format("%02x", b));
    }
    return sb.toString();
  }

  /**
   * Converts a hex string to a byte array.
   *
   * @param hex the hex string to convert
   * @return a byte array representing the given hexadecimal string
   * @throws IllegalArgumentException if the input string has an odd length
   */
  public static byte[] hexToBytes(String hex) {
    int len = hex.length();
    if (len % 2 != 0) {
      throw new IllegalArgumentException("Hex string must have an even length");
    }
    byte[] data = new byte[len / 2];
    for (int i = 0; i < len; i += 2) {
      data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
        + Character.digit(hex.charAt(i + 1), 16));
    }
    return data;
  }
}
