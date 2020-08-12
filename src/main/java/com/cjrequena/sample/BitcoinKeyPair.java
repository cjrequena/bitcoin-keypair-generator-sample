package com.cjrequena.sample;

import lombok.Data;
import lombok.extern.log4j.Log4j2;

/**
 * <p>
 * <p>
 * <p>
 * <p>
 * @author cjrequena
 *
 */
@Data
@Log4j2
public class BitcoinKeyPair {

  private String privateKey;
  private String privateKeyWIF;
  private String publicKey;
  private String address;
  private Boolean compressed;
}
