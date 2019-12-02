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
    log.info("Private Key: {}", bitcoinPrivateKey);

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
    log.info("Public Key: {}", bitcoinPublicKey);

    bitcoinKeyPair.setPrivateKey(bitcoinPrivateKey);
    bitcoinKeyPair.setPublicKey(bitcoinPublicKey);
    return bitcoinKeyPair;
  }


}
