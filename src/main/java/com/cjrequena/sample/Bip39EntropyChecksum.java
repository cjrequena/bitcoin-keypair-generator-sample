package com.cjrequena.sample;

import lombok.extern.log4j.Log4j2;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;

/**
 * Computes and validates the BIP-39 checksum for wallet entropy.
 * <p>BIP-39 turns random entropy into a mnemonic sentence. Before the entropy is
 * split into 11-bit groups (one per mnemonic word), a short checksum is appended
 * so that a typo in the mnemonic can be detected. This class produces and verifies
 * that {@code entropy + checksum} bit string, and {@link #toMnemonic(String)} maps the
 * 11-bit groups to their words using the bundled BIP-39 English wordlist.
 * <p>The rules, straight from the specification:
 * <ul>
 *   <li>The entropy (ENT) is one of 128, 160, 192, 224 or 256 bits.</li>
 *   <li>The checksum (CS) is {@code ENT / 32} bits long.</li>
 *   <li>The checksum equals the first {@code CS} bits of {@code SHA-256(entropy)}.</li>
 *   <li>The total {@code ENT + CS} length is always a multiple of 11, so it divides
 *       evenly into mnemonic words.</li>
 * </ul>
 * <table border="1">
 *   <caption>Supported sizes</caption>
 *   <tr><th>ENT (bits)</th><th>CS (bits)</th><th>ENT+CS</th><th>Words</th></tr>
 *   <tr><td>128</td><td>4</td><td>132</td><td>12</td></tr>
 *   <tr><td>160</td><td>5</td><td>165</td><td>15</td></tr>
 *   <tr><td>192</td><td>6</td><td>198</td><td>18</td></tr>
 *   <tr><td>224</td><td>7</td><td>231</td><td>21</td></tr>
 *   <tr><td>256</td><td>8</td><td>264</td><td>24</td></tr>
 * </table>
 * <p>Typical usage:
 * <pre>{@code
 * String bits = Bip39EntropyChecksum.fromHex("000102030405060708090a0b0c0d0e0f");
 * boolean ok  = Bip39EntropyChecksum.validate(bits); // true
 * }</pre>
 * <p>This class is stateless and thread-safe. All methods are static; it cannot be
 * instantiated.
 *
 * @see <a href="https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki">BIP-39</a>
 */
@Log4j2
public final class Bip39EntropyChecksum {

  /** Valid BIP-39 entropy sizes, in bits. */
  private static final Set<Integer> VALID_ENTROPY_BITS = Set.of(128, 160, 192, 224, 256);

  /** Divisor that relates entropy length to checksum length: {@code CS = ENT / 32}. */
  private static final int CHECKSUM_DIVISOR = 32;

  /** Number of bits encoded by a single mnemonic word ({@code 2^11 == 2048} words). */
  private static final int BITS_PER_WORD = 11;

  /** Classpath location of the BIP-39 English wordlist (2048 words, one per line). */
  private static final String WORD_LIST_RESOURCE = "/word-list.txt";

  /** The 2048-word BIP-39 list, loaded once from the classpath on first use. */
  private static final List<String> WORD_LIST = loadWordList();

  private Bip39EntropyChecksum() {
    // Utility class - no instances.
  }

  /**
   * Computes the BIP-39 entropy + checksum bit string from hex-encoded entropy.
   *
   * @param entropyHex entropy as a hex string (32, 40, 48, 56 or 64 hex chars)
   * @return {@code ENT + CS} bit binary string
   * @throws IllegalArgumentException if the hex is malformed or the length is invalid
   */
  public static String fromHex(String entropyHex) {
    if (entropyHex == null) {
      throw new IllegalArgumentException("Entropy hex must not be null");
    }
    byte[] entropy;
    try {
      entropy = HexFormat.of().parseHex(entropyHex);
    } catch (IllegalArgumentException e) {
      throw new IllegalArgumentException("Entropy must be a valid hex string", e);
    }
    validateEntropyLength(entropy.length * 8);

    return bytesToBinary(entropy) + calculateChecksum(entropy);
  }

  /**
   * Computes the BIP-39 entropy + checksum bit string from binary-encoded entropy.
   *
   * @param entropyBits entropy as a binary string (128, 160, 192, 224 or 256 chars)
   * @return {@code ENT + CS} bit binary string
   * @throws IllegalArgumentException if the string is not binary or the length is invalid
   */
  public static String fromBinary(String entropyBits) {
    if (entropyBits == null) {
      throw new IllegalArgumentException("Entropy bits must not be null");
    }
    validateEntropyLength(entropyBits.length());

    byte[] entropy = binaryToBytes(entropyBits);

    return entropyBits + calculateChecksum(entropy);
  }

  /**
   * Validates a full BIP-39 {@code ENT + CS} bit string by recomputing the checksum.
   *
   * @param entropyAndChecksumBits binary string of entropy followed by its checksum
   * @return {@code true} if the trailing checksum matches the recomputed one
   * @throws IllegalArgumentException if the string is null, not binary, or has an invalid length
   */
  public static boolean validate(String entropyAndChecksumBits) {
    if (entropyAndChecksumBits == null) {
      throw new IllegalArgumentException("Entropy + checksum bits must not be null");
    }

    int totalBits = entropyAndChecksumBits.length();
    // total = ENT + ENT/32 = ENT * 33/32, so ENT = total * 32 / 33.
    int entropyBits = totalBits * CHECKSUM_DIVISOR / (CHECKSUM_DIVISOR + 1);
    validateEntropyLength(entropyBits);

    if (entropyBits + entropyBits / CHECKSUM_DIVISOR != totalBits) {
      throw new IllegalArgumentException("Invalid total length " + totalBits + " bits for a BIP-39 entropy + checksum");
    }

    String entropyPart = entropyAndChecksumBits.substring(0, entropyBits);
    String checksumPart = entropyAndChecksumBits.substring(entropyBits);

    String expected = calculateChecksum(binaryToBytes(entropyPart));
    return expected.equals(checksumPart);
  }

  /**
   * Converts a full BIP-39 {@code ENT + CS} bit string into its mnemonic words.
   * <p>The bit string is split into groups of {@value #BITS_PER_WORD} bits; each
   * group is read as an unsigned index into the BIP-39 wordlist. The input is
   * typically the output of {@link #fromHex(String)} or {@link #fromBinary(String)}.
   *
   * @param entropyAndChecksumBits binary string whose length is a multiple of 11
   * @return the ordered list of mnemonic words (12, 15, 18, 21 or 24 of them)
   * @throws IllegalArgumentException if the string is null, not binary, or its length
   *                                  is not a multiple of {@value #BITS_PER_WORD}
   */
  public static List<String> toMnemonic(String entropyAndChecksumBits) {
    if (entropyAndChecksumBits == null) {
      throw new IllegalArgumentException("Entropy + checksum bits must not be null");
    }
    if (entropyAndChecksumBits.length() % BITS_PER_WORD != 0) {
      throw new IllegalArgumentException(
        "Bit length must be a multiple of " + BITS_PER_WORD + ", but was "
          + entropyAndChecksumBits.length());
    }

    int wordCount = entropyAndChecksumBits.length() / BITS_PER_WORD;
    List<String> words = new ArrayList<>(wordCount);
    for (int i = 0; i < wordCount; i++) {
      String group = entropyAndChecksumBits.substring(i * BITS_PER_WORD, (i + 1) * BITS_PER_WORD);
      int index = parseBinaryIndex(group);
      words.add(WORD_LIST.get(index));
    }
    return words;
  }

  /** Convenience wrapper returning the mnemonic as a single space-separated sentence. */
  public static String toMnemonicSentence(String entropyAndChecksumBits) {
    return String.join(" ", toMnemonic(entropyAndChecksumBits));
  }

  /**
   * BIP-39 checksum: the first {@code ENT / 32} bits of {@code SHA-256(entropy)}.
   */
  private static String calculateChecksum(byte[] entropy) {
    byte[] hash = sha256(entropy);
    int checksumLength = entropy.length * 8 / CHECKSUM_DIVISOR;
    return bytesToBinary(hash).substring(0, checksumLength);
  }

  private static byte[] sha256(byte[] input) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(input);
    } catch (NoSuchAlgorithmException e) {
      // SHA-256 is a required algorithm on every JVM; this should never happen.
      throw new IllegalStateException("SHA-256 algorithm not available", e);
    }
  }

  /** Parses an 11-bit binary group into its unsigned wordlist index (0..2047). */
  private static int parseBinaryIndex(String group) {
    int index = 0;
    for (int i = 0; i < group.length(); i++) {
      char c = group.charAt(i);
      if (c != '0' && c != '1') {
        throw new IllegalArgumentException("Bits must be a binary string (only '0' and '1')");
      }
      index = (index << 1) | (c - '0');
    }
    return index;
  }

  /** Loads the BIP-39 wordlist from the classpath; fails fast if it is missing or malformed. */
  private static List<String> loadWordList() {
    try (InputStream in = Bip39EntropyChecksum.class.getResourceAsStream(WORD_LIST_RESOURCE)) {
      if (in == null) {
        throw new IllegalStateException("Wordlist resource not found: " + WORD_LIST_RESOURCE);
      }
      List<String> words = new ArrayList<>(1 << BITS_PER_WORD);
      try (BufferedReader reader =
        new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
        String line;
        while ((line = reader.readLine()) != null) {
          line = line.strip();
          if (!line.isEmpty()) {
            words.add(line);
          }
        }
      }
      int expected = 1 << BITS_PER_WORD;
      if (words.size() != expected) {
        throw new IllegalStateException(
          "Wordlist must contain exactly " + expected + " words, but had " + words.size());
      }
      return List.copyOf(words);
    } catch (IOException e) {
      throw new UncheckedIOException("Failed to read wordlist: " + WORD_LIST_RESOURCE, e);
    }
  }

  private static void validateEntropyLength(int entropyBits) {
    if (!VALID_ENTROPY_BITS.contains(entropyBits)) {
      throw new IllegalArgumentException("Entropy must be one of " + VALID_ENTROPY_BITS + " bits, but was " + entropyBits);
    }
  }

  /** Renders bytes as a big-endian binary string, 8 characters per byte. */
  private static String bytesToBinary(byte[] bytes) {
    StringBuilder result = new StringBuilder(bytes.length * 8);
    for (byte b : bytes) {
      for (int bit = 7; bit >= 0; bit--) {
        result.append((b >> bit) & 1);
      }
    }
    return result.toString();
  }

  /** Parses a binary string (length a multiple of 8) back into big-endian bytes. */
  private static byte[] binaryToBytes(String bits) {
    if (bits.length() % 8 != 0) {
      throw new IllegalArgumentException("Binary length must be a multiple of 8");
    }
    byte[] bytes = new byte[bits.length() / 8];
    for (int i = 0; i < bytes.length; i++) {
      int value = 0;
      for (int bit = 0; bit < 8; bit++) {
        char c = bits.charAt(i * 8 + bit);
        if (c != '0' && c != '1') {
          throw new IllegalArgumentException("Entropy must be a binary string (only '0' and '1')");
        }
        value = (value << 1) | (c - '0');
      }
      bytes[i] = (byte) value;
    }
    return bytes;
  }

  public static void main(String[] args) {

    // Example 128-bit entropy
    String hexEntropy = "000102030405060708090a0b0c0d0e0f";

    String result1 = fromHex(hexEntropy);

    log.info("From hex: {}", hexEntropy);
    log.info("Checksum Result: {}", result1);
    log.info("Length: {}", result1.length());
    log.info("Valid: {}", validate(result1));
    log.info("Mnemonic: {}", toMnemonicSentence(result1));

    System.out.println("\n ============================================================================================================== \n");

    String binaryEntropy128 =
      "000000000000000100000010000000110000010000000101" +
        "000001100000011100001000000010010000101000001011" +
        "00001100000011010000111000001111";

    String result2 = fromBinary(binaryEntropy128);

    log.info("From binary 128: {}", binaryEntropy128);
    log.info("Checksum Result: {}", result2);
    log.info("Length: {}", result2.length());
    log.info("Valid: {}", validate(result2));
    log.info("Mnemonic: {}", toMnemonicSentence(result2));

    System.out.println("\n ============================================================================================================== \n");

    String binaryEntropy256 =
      "000000000000000100000010000000110000010000000101" +
        "000001100000011100001000000010010000101000001011" +
        "00001100000011010000111000001111" +
        "000000000000000100000010000000110000010000000101" +
        "000001100000011100001000000010010000101000001011" +
        "00001100000011010000111000001111";

    String result3 = fromBinary(binaryEntropy256);

    log.info("From binary 256: {}", binaryEntropy256);
    log.info("Checksum Result: {}", result3);
    log.info("Length: {}", result3.length());
    log.info("Valid: {}", validate(result3));
    log.info("Mnemonic: {}", toMnemonicSentence(result3));

    System.out.println("\n ============================================================================================================== \n");

    // Tamper with the checksum to show validation failing.
    String tampered = result1.substring(0, result1.length() - 1) + (result1.endsWith("0") ? "1" : "0");
    log.info("Tampered valid: {}", validate(tampered));
  }
}
