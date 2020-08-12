package com.cjrequena.sample;

import lombok.extern.log4j.Log4j2;
import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;

import static org.junit.Assert.*;

/**
 * <p>
 * <p>
 * <p>
 * <p>
 * @author cjrequena
 *
 */
@Log4j2
public class BitcoinKeyPairGeneratorTest {

  @Before
  public void setUp() throws Exception {
  }

  @After
  public void tearDown() throws Exception {
  }

  @Test
  @Ignore
  public void generateECKeyPair() {
    try {
      KeyPair keyPair = BitcoinKeyPairGenerator.generateECKeyPair();
      //Private Key
      final PrivateKey privateKey = keyPair.getPrivate();
      ECPrivateKey ecPrivateKey = (ECPrivateKey) privateKey;

      log.info("ECPrivate Key Base 10: {}", ecPrivateKey.getS().toString());
      log.info("ECPrivate Key Base 2: {}", ecPrivateKey.getS().toString(2));
      log.info("ECPrivate Key Base 16: {}", ecPrivateKey.getS().toString(16));
      assertTrue(privateKey.getAlgorithm().equals("EC"));
      assertTrue(ecPrivateKey.getParams().getCurve().getA().equals(BigInteger.ZERO));
      assertTrue(ecPrivateKey.getParams().getCurve().getB().equals(BigInteger.valueOf(7)));
      assertTrue(ecPrivateKey.getS().toString(2).length() <= 256);

    } catch (NoSuchAlgorithmException ex) {
      fail(ex.getMessage());
    } catch (InvalidAlgorithmParameterException ex) {
      fail(ex.getMessage());
    }
  }

  @Test
  public void generateBitcoinKeyPairTest() {
    try {
      BitcoinKeyPair bitcoinKeyPair = BitcoinKeyPairGenerator.generateBitcoinKeyPair(true);
      log.debug("Bitcoin Address: {}", bitcoinKeyPair.getAddress());
      log.debug("Is Compressed: {}", bitcoinKeyPair.getCompressed());
      log.debug("Bitcoin Private Key WIF: {}", bitcoinKeyPair.getPrivateKeyWIF());

    } catch (NoSuchAlgorithmException ex) {
      fail(ex.getMessage());
    } catch (InvalidAlgorithmParameterException ex) {
      fail(ex.getMessage());
    } catch (NoSuchProviderException ex) {
      fail(ex.getMessage());
    } catch (Exception ex) {
      ex.printStackTrace();
    }
  }
}
