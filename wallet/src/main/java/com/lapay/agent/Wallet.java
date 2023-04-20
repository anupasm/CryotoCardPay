package com.lapay.agent;

import javacard.framework.Util;

public class Wallet {
    public static byte[] localBalance;
    public static byte[] remoteBalance;
    public static byte[] payAmount;

    public static byte[] c;
    public static byte[] a;
    public static byte[] x;


    public static void init() {
        remoteBalance = new byte[8];
        Util.arrayCopy(REMOTE_BALANCE,(short)0,remoteBalance,(short)0,(short)8);

        localBalance = new byte[]{(byte) 0x0,(byte) 0x0,(byte) 0x0,(byte) 0x0,(byte) 0x0,(byte) 0x0,(byte) 0x0,(byte) 0x0};
        payAmount = new byte[]{(byte) 0x0,(byte) 0x0,(byte) 0x0,(byte) 0x0,(byte) 0x0,(byte) 0x0,(byte) 0x0,(byte) 0x0};       
        
        c = new byte[8];
        a = new byte[8];
        x = new byte[8];
        
    }

    public static void updatePayAmount(byte[] payAmount){

		//todo check balance

		//store pay amount in wallet x
		Util.arrayCopy(payAmount, (short) 0, Wallet.x, (short)0, Tx.TX_VALUE_SIZE);

		// get agent balance, add the pay amount, store in wallet a
		CryptoA.num1.fromByteArray(Wallet.localBalance, (short) 0, Tx.TX_VALUE_SIZE);
		CryptoA.num2.fromByteArray(Wallet.payAmount, (short) 0, Tx.TX_VALUE_SIZE);
		CryptoA.num1.add(CryptoA.num2);
		CryptoA.num1.toByteArrayUnsigned(Wallet.a, (short) 0);

		// get card balance, subtract the pay amount, store in wallet balance

		CryptoA.num1.fromByteArray(Wallet.remoteBalance, (short) 0, Tx.TX_VALUE_SIZE);
		CryptoA.num2.fromByteArray(payAmount, (short) 0, Tx.TX_VALUE_SIZE);
		CryptoA.num1.subtract(CryptoA.num2);
		CryptoA.num1.toByteArrayUnsigned(Wallet.c, (short) 0);
	}


    final static byte[] REMOTE_BALANCE = new byte[]{(byte) 0x0,(byte) 0x0,(byte) 0x0,(byte) 0x0, (byte) 0x05, (byte)0xF5, (byte)0xE1, (byte)0x00}; //100 000 000


}
