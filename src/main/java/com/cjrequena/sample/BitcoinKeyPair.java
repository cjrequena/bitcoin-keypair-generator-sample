package com.cjrequena.sample;

import lombok.Data;
import lombok.extern.log4j.Log4j2;
import org.bitcoinj.core.Base58;

import javax.xml.bind.DatatypeConverter;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

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

  /**
   *
   * @return
   */
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

  /**
   *
   * @return
   */
  public String getAddress()  {
    try {
      // 1.- Take the Public key
      // 2.-  Perform SHA-256 hashing on the public key. [https://en.bitcoin.it/wiki/SHA-256]
      // The public key will be converted to binary before hashing.
      // This is the way things are hashed internally in bitcoin. (e.g. when creating a transaction ID)
      MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
      byte[] sha1 = sha256.digest(DatatypeConverter.parseHexBinary(publicKey));
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
      this.address = Base58.encode(hexToBytes(ripeMDExtendedAndChecksum));
      log.info("Address: {}", address);
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    } catch (NoSuchProviderException e) {
      e.printStackTrace();
    }
    return this.address;
  }
}
