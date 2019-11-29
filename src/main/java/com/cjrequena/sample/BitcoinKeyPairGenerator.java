package com.cjrequena.sample;

import lombok.extern.log4j.Log4j2;
import org.bitcoinj.core.Base58;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.xml.bind.DatatypeConverter;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.InvalidKeySpecException;
import java.util.Random;

/**
 * <p>
 * <p>
 * <p>
 * <p>
 * @author cjrequena
 *
 */
@Log4j2
public class BitcoinKeyPairGenerator {

  private static String SECP256K1 = "secp256k1";

  static {
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  /**
   *
   * @return
   * @throws NoSuchAlgorithmException
   * @throws InvalidAlgorithmParameterException
   */
  public static KeyPair generateECKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
    ECGenParameterSpec parameterSpec = new ECGenParameterSpec(SECP256K1);
    SecureRandom secureRandom = new SecureRandom();
    secureRandom.setSeed(new Random().nextLong());
    keyGen.initialize(parameterSpec, secureRandom);
    KeyPair keyPair = keyGen.generateKeyPair();
    return keyPair;
  }

  /**
   *
   * @param compressed
   * @return
   * @throws InvalidAlgorithmParameterException
   * @throws NoSuchAlgorithmException
   * @throws NoSuchProviderException
   * @throws InvalidKeySpecException
   * @throws UnsupportedEncodingException
   */
  public static BitcoinKeyPair generateBitcoinKeyPair(boolean compressed)
    throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, UnsupportedEncodingException {

    String bitcoinPublicKey = null;
    String bitcoinPrivateKey = null;
    String bitcoinAddress = null;

    //****************************
    // Generate ECDSA Key Pair
    //****************************
    KeyPair keyPair = generateECKeyPair();

    // 0.- The Private Key
    ECPrivateKey ecPrivateKey = (ECPrivateKey) keyPair.getPrivate();
    bitcoinPrivateKey = adjustTo64(ecPrivateKey.getS().toString(16)).toUpperCase();
    log.info("Private Key: {}", bitcoinPrivateKey);

    ECPublicKey ecPublicKey = (ECPublicKey) keyPair.getPublic();
    ECPoint ecPoint = ecPublicKey.getW();
    String sxBase2 = ecPoint.getAffineX().toString(2).toUpperCase();
    String syBase2 = ecPoint.getAffineY().toString(2).toUpperCase();
    String sxBase16 = adjustTo64(ecPoint.getAffineX().toString(16)).toUpperCase();
    String syBase16 = adjustTo64(ecPoint.getAffineY().toString(16)).toUpperCase();

    //    log.info("sxBase2: {}", sxBase2);
    //    log.info("syBase2: {}", syBase2);
    //    log.info("sxBase16: {}", sxBase16);
    //    log.info("syBase16: {}", syBase16);

    // 1.- The Public Key
    if (!compressed) {
      //****************************
      // [uncompressed] This is the old format. It has generally stopped being used in favor of the shorter compressed format.
      // In this uncompressed format, you just place the x and y coordinate next to each other, then prefix the whole thing with an 04
      //****************************
      bitcoinPublicKey = "04" + sxBase16 + syBase16;
    } else {
      //****************************
      // [compressed] Take the corresponding public key generated with it (33 bytes, 1 byte 0x02 (y-coord is even) 0x03 (y-coord is odd), and 32 bytes corresponding to X coordinate)
      // If the last binary digit of the y coordinate is 0, then the number is even, which corresponds to positive. If it is 1, then it is negative.
      //****************************
      if (syBase2.charAt(syBase2.length() - 1) == '0') {
        bitcoinPublicKey = "02" + sxBase16;
      } else {
        bitcoinPublicKey = "03" + sxBase16;
      }
    }

    log.info("Public Key: {}", bitcoinPublicKey);

    // 2.-  Perform SHA-256 hashing on the public key. [https://en.bitcoin.it/wiki/SHA-256]
    // The public key will be converted to binary before hashing.
    // This is the way things are hashed internally in bitcoin. (e.g. when creating a transaction ID)
    MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
    byte[] sha1 = sha256.digest(DatatypeConverter.parseHexBinary(bitcoinPublicKey));
    //byte[] s1 = sha256.digest(bitcoinPublicKey.getBytes(StandardCharsets.UTF_8));
    log.info("Sha1: {}", bytesToHex(sha1).toUpperCase());

    // 3.- Perform RIPEMD-160 hashing on the result of SHA-256 [https://en.bitcoin.it/wiki/RIPEMD-160]
    MessageDigest ripeMD160Digest = MessageDigest.getInstance("RipeMD160", "BC");
    byte[] ripeMD = ripeMD160Digest.digest(sha1);
    log.info("RipeMD160: {}", bytesToHex(ripeMD).toUpperCase());

    // 4.- Add version byte in front of RIPEMD-160 hash (0x00 for Main Network)
    byte[] ripeMDExtended = hexToBytes("00" + bytesToHex(ripeMD));
    log.info("RipeMD160Extended: {}", bytesToHex(ripeMDExtended).toUpperCase());

    // 5.- Perform SHA-256 hash on the extended RIPEMD-160 result
    byte[] sha2 = sha256.digest(ripeMDExtended);
    log.info("Sha2: {}", bytesToHex(sha2).toUpperCase());

    // 6.- Perform SHA-256 hash on the result of the previous SHA-256 hash
    byte[] sha3 = sha256.digest(sha2);
    log.info("Sha3: {}", bytesToHex(sha3).toUpperCase());

    // 7.- Take the first 4 bytes of the previous hash SHA-256 hash. This is the address checksum
    String checksum = bytesToHex(sha3).substring(0, 8).toUpperCase();
    log.info("Checksum: {}", checksum);

    // 8.- Add the 4 checksum bytes from stage 7 at the end of extended RIPEMD-160 hash from stage 4. This is the 25-byte binary Bitcoin Address.
    //    byte[] sumBytes = new byte[25];
    //    System.arraycopy(ripeMDExtended, 0, sumBytes, 0, 21);
    //    System.arraycopy(sha3, 0, sumBytes, 21, 4);
    String ripeMDExtendedAndChecksum = bytesToHex(ripeMDExtended) + checksum;
    log.info("RipeMDExtended + Checksum: {}", ripeMDExtendedAndChecksum.toUpperCase());

    // 9.- Convert the result from a byte string into a base58 string using Base58Check encoding. This is the most commonly used Bitcoin Address format
    //bitcoinAddress = Base58.encode(sumBytes);
    bitcoinAddress = Base58.encode(hexToBytes(ripeMDExtendedAndChecksum));
    log.info("Address: {}", bitcoinAddress);

    BitcoinKeyPair bitcoinKeyPair = new BitcoinKeyPair();
    bitcoinKeyPair.setPrivateKey(bitcoinPrivateKey);
    bitcoinKeyPair.setPublicKey(bitcoinPublicKey);
    bitcoinKeyPair.setAddress(bitcoinAddress);
    return bitcoinKeyPair;
  }

  /**
   *
   * @param hex
   * @return
   */
  private static String adjustTo64(String hex) {
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
  private static String bytesToHex(byte[] bytes) {
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
  private static byte[] hexToBytes(String hex) {
    int len = hex.length();
    byte[] data = new byte[len / 2];
    for (int i = 0; i < len; i += 2) {
      data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
        + Character.digit(hex.charAt(i + 1), 16));
    }
    return data;
  }

}
