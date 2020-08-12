package com.cjrequena.sample.checkbalance;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import lombok.Data;

/**
 * <p>
 * <p>
 * <p>
 * <p>
 * @author cjrequena
 *
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({
  "address",
  "total_received",
  "total_sent",
  "balance",
  "unconfirmed_balance",
  "final_balance",
  "n_tx",
  "unconfirmed_n_tx",
  "final_n_tx"
})
@Data
public class BalanceDTO {


  @JsonProperty("address")
  private String address;
  @JsonProperty("private_key_wif")
  private String privateKeyWif;
  @JsonProperty("total_received")
  private Integer totalReceived;
  @JsonProperty("total_sent")
  private Integer totalSent;
  @JsonProperty("balance")
  private Integer balance;
  @JsonProperty("unconfirmed_balance")
  private Integer unconfirmedBalance;
  @JsonProperty("final_balance")
  private Integer finalBalance;
  @JsonProperty("n_tx")
  private Integer nTx;
  @JsonProperty("unconfirmed_n_tx")
  private Integer unconfirmedNTx;
  @JsonProperty("final_n_tx")
  private Integer finalNTx;
}
