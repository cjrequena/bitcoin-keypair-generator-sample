package com.cjrequena.sample;

import lombok.Data;
import lombok.extern.log4j.Log4j2;
import org.bitcoinj.core.Base58;

import javax.xml.bind.DatatypeConverter;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

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
@Data
@Log4j2
public class BitcoinKeyPair {
  private String privateKey;
  private String privateKeyWIF;
  private String publicKey;
  private String address;
  private Boolean compressed;


  public String getPrivateKeyWIF()  {

    try {
      // 1 - Take a private key
      // 2 - Add a 0x80 byte in front of it for mainnet addresses or 0xef for testnet addresses.
      // Also add a 0x01 byte at the end if the private key will correspond to a compressed public key
      if(this.compressed){
        this.privateKeyWIF = "80" + this.privateKey + "01";
      }else {
        this.privateKeyWIF = "80" + this.privateKey;
      }

      // 3 - Perform SHA-256 hash on the extended key
      MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
      byte[] sha1 = sha256.digest(DatatypeConverter.parseHexBinary(privateKeyWIF));
      //log.info("Sha1: {}", bytesToHex(sha1).toUpperCase());

      // 4 - Perform SHA-256 hash on result of SHA-256 hash
      byte[] sha2 = sha256.digest(sha1);
      //log.info("Sha2: {}", bytesToHex(sha2).toUpperCase());

      // 5 - Take the first 4 bytes of the second SHA-256 hash, this is the checksum
      String checksum = bytesToHex(sha2).substring(0, 8).toUpperCase();
      //log.info("Checksum: {}", checksum);

      // 6 - Add the 4 checksum bytes from point 5 at the end of the extended key from point 2
      String privateKeyWIF = this.privateKeyWIF + checksum;
      //log.info("Private Key + Checksum: {}", privateKeyWIF.toUpperCase());

      // 7 - Convert the result from a byte string into a base58 string using Base58Check encoding. This is the Wallet Import Format
      privateKeyWIF = Base58.encode(hexToBytes(privateKeyWIF));
      //log.info("Private Key WIF: {}", privateKeyWIF);
      return privateKeyWIF;
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
      return null;
    }
  }
}
