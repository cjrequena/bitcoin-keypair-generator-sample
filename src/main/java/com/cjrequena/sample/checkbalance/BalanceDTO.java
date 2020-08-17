package com.cjrequena.sample.checkbalance;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import lombok.Data;

import java.math.BigDecimal;

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
  private double totalReceived;
  @JsonProperty("total_sent")
  private double totalSent;
  @JsonProperty("balance")
  private double balance;
  @JsonProperty("unconfirmed_balance")
  private double unconfirmedBalance;
  @JsonProperty("final_balance")
  private double finalBalance;
  @JsonProperty("n_tx")
  private Integer nTx;
  @JsonProperty("unconfirmed_n_tx")
  private Integer unconfirmedNTx;
  @JsonProperty("final_n_tx")
  private Integer finalNTx;

  public double getTotalReceived(){
    if(this.totalReceived % 1 == 0) {
      return this.totalReceived / 1e8d;
    }else{
      return this.totalReceived;
    }
  }
  public double getTotalSent(){
    if(this.totalSent % 1 == 0) {
      return this.totalSent / 1e8d;
    }else{
      return this.totalSent;
    }
  }

  public double getBalance(){
    if(this.balance % 1 == 0) {
      return this.balance / 1e8d;
    }else{
      return this.balance;
    }
  }

  public double getUnconfirmedBalance(){
    if(this.unconfirmedBalance % 1 == 0) {
      return this.unconfirmedBalance / 1e8d;
    }else{
      return this.unconfirmedBalance;
    }
  }

  public double getFinalBalance(){
    if(this.finalBalance % 1 == 0) {
      return this.finalBalance / 1e8d;
    }else{
      return this.finalBalance;
    }
  }
}
