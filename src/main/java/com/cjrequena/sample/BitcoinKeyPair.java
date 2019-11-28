package com.cjrequena.sample;

import lombok.Data;
import lombok.EqualsAndHashCode;

/**
 * <p>
 * <p>
 * <p>
 * <p>
 * @author cjrequena
 *
 */
@Data
@EqualsAndHashCode
public class BitcoinKeyPair {
  private String privateKey;
  private String publicKey;
  private String address;
}
