package com.cjrequena.sample;

import lombok.extern.log4j.Log4j2;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPrivateKey;

import static org.junit.jupiter.api.Assertions.*;

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

  @BeforeEach
  public void setUp() throws Exception {
  }

  @AfterEach
  public void tearDown() throws Exception {
  }

  @Test
  @Disabled
  public void generateECKeyPair() {
    try {
      KeyPair keyPair = BitcoinKeyPairGenerator.generateECKeyPair();
      // Private Key
      final PrivateKey privateKey = keyPair.getPrivate();
      ECPrivateKey ecPrivateKey = (ECPrivateKey) privateKey;

      log.info("ECPrivate Key Base 10: {}", ecPrivateKey.getS().toString());
      log.info("ECPrivate Key Base 2: {}", ecPrivateKey.getS().toString(2));
      log.info("ECPrivate Key Base 16: {}", ecPrivateKey.getS().toString(16));

      assertEquals("EC", privateKey.getAlgorithm());
      assertEquals(BigInteger.ZERO, ecPrivateKey.getParams().getCurve().getA());
      assertEquals(ecPrivateKey.getParams().getCurve().getB(), BigInteger.valueOf(7));
      assertTrue(ecPrivateKey.getS().toString(2).length() <= 256);

    } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | NoSuchProviderException ex) {
      fail(ex.getMessage());
    }
  }

  @Test
  public void generateBitcoinKeyPairTest() {
    try {
      System.out.println(Security.getProvider("BC"));
      BitcoinKeyPair bitcoinKeyPair = BitcoinKeyPairGenerator.generateBitcoinKeyPair(true);
      log.info("Bitcoin Address: {}", bitcoinKeyPair.getAddress());
      log.info("Is Compressed: {}", bitcoinKeyPair.getCompressed());
      log.info("Bitcoin Private Key WIF: {}", bitcoinKeyPair.getPrivateKeyWIF());

    } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | NoSuchProviderException ex) {
      fail(ex.getMessage());
    } catch (Exception ex) {
      ex.printStackTrace();
    }
  }
}
