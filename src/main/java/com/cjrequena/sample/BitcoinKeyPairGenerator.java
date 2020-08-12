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

import static com.cjrequena.sample.Utils.adjustTo64;
import static com.cjrequena.sample.Utils.bytesToHex;
import static com.cjrequena.sample.Utils.hexToBytes;

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

    BitcoinKeyPair bitcoinKeyPair = new BitcoinKeyPair();
    String bitcoinPublicKey = null;
    String bitcoinPrivateKey = null;

    //****************************
    // Generate ECDSA Key Pair
    //****************************
    KeyPair keyPair = generateECKeyPair();

    // 0.- The Private Key
    ECPrivateKey ecPrivateKey = (ECPrivateKey) keyPair.getPrivate();
    bitcoinPrivateKey = adjustTo64(ecPrivateKey.getS().toString(16)).toUpperCase();

    // 1.- The Public Key
    ECPublicKey ecPublicKey = (ECPublicKey) keyPair.getPublic();
    ECPoint ecPoint = ecPublicKey.getW();
    String sxBase2 = ecPoint.getAffineX().toString(2).toUpperCase();
    String syBase2 = ecPoint.getAffineY().toString(2).toUpperCase();
    String sxBase16 = adjustTo64(ecPoint.getAffineX().toString(16)).toUpperCase();
    String syBase16 = adjustTo64(ecPoint.getAffineY().toString(16)).toUpperCase();

    if (!compressed) {
      //****************************
      // [uncompressed] This is the old format. It has generally stopped being used in favor of the shorter compressed format.
      // In this uncompressed format, you just place the x and y coordinate next to each other, then prefix the whole thing with an 04
      //****************************
      bitcoinPublicKey = "04" + sxBase16 + syBase16;
      bitcoinKeyPair.setCompressed(Boolean.FALSE);
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
      bitcoinKeyPair.setCompressed(Boolean.TRUE);
    }

    String bitcoinPrivateKeyWIF = generateBitcoinPrivateKeyWIF(bitcoinPrivateKey, compressed);
    String bitcoinAddress = generateBitcoinAddress(bitcoinPublicKey);

    bitcoinKeyPair.setPrivateKey(bitcoinPrivateKey);
    bitcoinKeyPair.setPublicKey(bitcoinPublicKey);
    bitcoinKeyPair.setPrivateKeyWIF(bitcoinPrivateKeyWIF);
    bitcoinKeyPair.setAddress(bitcoinAddress);

    log.info("Private Key: {}", bitcoinPrivateKey);
    log.info("Public Key: {}", bitcoinPublicKey);
    log.debug("Private Key WIF {}", bitcoinPrivateKeyWIF);
    log.debug("Address {}", bitcoinAddress);
    return bitcoinKeyPair;
  }

  /**
   *
   * @return
   */
  public static String generateBitcoinPrivateKeyWIF(String privateKey, boolean compressed) {
    try {
      String privateKeyWIF = null;
      // 1 - Take a private key
      // 2 - Add a 0x80 byte in front of it for mainnet addresses or 0xef for testnet addresses.
      // Also add a 0x01 byte at the end if the private key will correspond to a compressed public key
      if (compressed) {
        privateKeyWIF = "80" + privateKey + "01";
      } else {
        privateKeyWIF = "80" + privateKey;
      }

      // 3 - Perform SHA-256 hash on the extended key
      MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
      byte[] sha1 = sha256.digest(DatatypeConverter.parseHexBinary(privateKeyWIF));
      //log.debug("Sha256-1: {}", bytesToHex(sha1).toUpperCase());

      // 4 - Perform SHA-256 hash on result of SHA-256 hash
      byte[] sha2 = sha256.digest(sha1);
      //log.debug("Sha256-2: {}", bytesToHex(sha2).toUpperCase());

      // 5 - Take the first 4 bytes of the second SHA-256 hash, this is the checksum
      String checksum = bytesToHex(sha2).substring(0, 8).toUpperCase();
      //log.debug("Checksum: {}", checksum);

      // 6 - Add the 4 checksum bytes from point 5 at the end of the extended key from point 2
      privateKeyWIF = privateKeyWIF + checksum;
      //log.debug("Private Key + Checksum: {}", privateKeyWIF.toUpperCase());

      // 7 - Convert the result from a byte string into a base58 string using Base58Check encoding. This is the Wallet Import Format
      privateKeyWIF = Base58.encode(hexToBytes(privateKeyWIF));
      //log.debug("Private Key WIF: {}", privateKeyWIF);
      return privateKeyWIF;
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
      return null;
    }
  }

  /**
   *
   * @return
   */
  public static String generateBitcoinAddress(String publicKey) {
    try {
      String address = null;

      // 1.- Take the Public key
      // 2.-  Perform SHA-256 hashing on the public key. [https://en.bitcoin.it/wiki/SHA-256]
      // The public key will be converted to binary before hashing.
      // This is the way things are hashed internally in bitcoin. (e.g. when creating a transaction ID)
      MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
      byte[] sha1 = sha256.digest(DatatypeConverter.parseHexBinary(publicKey));
      //log.debug("Sha256-1: {}", bytesToHex(sha1).toUpperCase());

      // 3.- Perform RIPEMD-160 hashing on the result of SHA-256 [https://en.bitcoin.it/wiki/RIPEMD-160]
      MessageDigest ripeMD160Digest = MessageDigest.getInstance("RipeMD160", "BC");
      byte[] ripeMD = ripeMD160Digest.digest(sha1);
      //log.debug("RipeMD160: {}", bytesToHex(ripeMD).toUpperCase());

      // 4.- Add version byte in front of RIPEMD-160 hash (0x00 for Main Network)
      byte[] ripeMDExtended = hexToBytes("00" + bytesToHex(ripeMD));
      //log.debug("RipeMD160Extended: {}", bytesToHex(ripeMDExtended).toUpperCase());

      // 5.- Perform SHA-256 hash on the extended RIPEMD-160 result
      byte[] sha2 = sha256.digest(ripeMDExtended);
      //log.debug("Sha256-2: {}", bytesToHex(sha2).toUpperCase());

      // 6.- Perform SHA-256 hash on the result of the previous SHA-256 hash
      byte[] sha3 = sha256.digest(sha2);
      //log.debug("Sha256-3: {}", bytesToHex(sha3).toUpperCase());

      // 7.- Take the first 4 bytes of the previous hash SHA-256 hash. This is the address checksum
      String checksum = bytesToHex(sha3).substring(0, 8).toUpperCase();
      //log.debug("Checksum: {}", checksum);

      // 8.- Add the 4 checksum bytes from stage 7 at the end of extended RIPEMD-160 hash from stage 4. This is the 25-byte binary Bitcoin Address.
      String ripeMDExtendedAndChecksum = bytesToHex(ripeMDExtended) + checksum;
      //log.debug("RipeMDExtended + Checksum: {}", ripeMDExtendedAndChecksum.toUpperCase());

      // 9.- Convert the result from a byte string into a base58 string using Base58Check encoding. This is the most commonly used Bitcoin Address format
      address = Base58.encode(hexToBytes(ripeMDExtendedAndChecksum));
      //log.debug("Bitcoin Address:  {}", address);
      return address;
    } catch (NoSuchAlgorithmException ex) {
      ex.printStackTrace();
      return null;
    } catch (NoSuchProviderException ex) {
      ex.printStackTrace();
      return null;
    }
  }

}
