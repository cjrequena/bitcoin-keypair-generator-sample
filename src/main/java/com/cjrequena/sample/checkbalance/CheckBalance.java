package com.cjrequena.sample.checkbalance;

import com.cjrequena.sample.BitcoinKeyPair;
import com.cjrequena.sample.BitcoinKeyPairGenerator;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.log4j.Log4j2;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.net.URL;
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
public class CheckBalance {

  public static void main(String[] arg) {
    checkBalance();
  }

  private static void checkBalance() {
    BufferedWriter writer;
    int ONE_MINUTE = 60000;
    int TWENTY_MINUTES = 1200000;

    int count = 1;
    while (true) {
      try {
        Random rd = new Random(); // creating Random object
        BitcoinKeyPair bitcoinKeyPair = BitcoinKeyPairGenerator.generateBitcoinKeyPair(rd.nextBoolean());
        // writer = new BufferedWriter(new FileWriter("private_keys_wif.txt", true));
        // writer.append(bitcoinKeyPair.getPrivateKeyWIF() + "\n");
        // writer.close();

        String url = "https://api.blockcypher.com/v1/btc/main/addrs/" + bitcoinKeyPair.getAddress() + "/balance";

        ObjectMapper mapper = new ObjectMapper();
        //JSON URL to Java object
        BalanceDTO balanceDTO = mapper.readValue(new URL(url), BalanceDTO.class);
        balanceDTO.setPrivateKeyWif(bitcoinKeyPair.getPrivateKeyWIF());
        if (balanceDTO.getBalance() > 0 || balanceDTO.getFinalBalance() > 0 || balanceDTO.getUnconfirmedBalance() > 0 || balanceDTO.getTotalReceived() > 0) {
          writer = new BufferedWriter(new FileWriter("balance.txt", true));
          //writer.append("========== \n");
          writer.append(balanceDTO.toString() + "\n");
          writer.close();
        }
        log.info(balanceDTO);
        if ((count >= 69)) {
          Thread.sleep(TWENTY_MINUTES);
          count = 0;
        }
        count++;
      } catch (Exception ex) {
        log.info("Count: {}", count);
        log.info(ex.getLocalizedMessage());
        break;

      }
    }
  }
}
