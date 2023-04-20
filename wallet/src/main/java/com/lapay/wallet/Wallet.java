package com.lapay.wallet;

import javacard.framework.Util;

public class Wallet {
    public static byte[] localBalance;
    public static byte[] remoteBalance;
    public static byte[] payAmount;


    public static byte[] c;
    public static byte[] a;
    public static byte[] x;

    public static void init() {
        localBalance = new byte[8];
        Util.arrayCopy(LOCAL_BALANCE,(short)0,localBalance,(short)0,(short)8);

        remoteBalance = new byte[]{(byte) 0x0,(byte) 0x0,(byte) 0x0,(byte) 0x0,(byte) 0x0,(byte) 0x0,(byte) 0x0,(byte) 0x0};
        payAmount = new byte[]{(byte) 0x0,(byte) 0x0,(byte) 0x0,(byte) 0x0,(byte) 0x0,(byte) 0x0,(byte) 0x0,(byte) 0x0};     
        
        c = new byte[8];
        a = new byte[8];
        x = new byte[8];
    }

    public static void updatePayAmount(byte[] buf){

		//todo check balance

		//store pay amount in wallet x
		Util.arrayCopy(buf, (short) 5, Wallet.x, (short)0, Tx.TX_VALUE_SIZE);

		// get agent balance, add the pay amount, store in wallet a
		CryptoC.num1.fromByteArray(Wallet.remoteBalance, (short) 0, Tx.TX_VALUE_SIZE);
		CryptoC.num2.fromByteArray(Wallet.payAmount, (short) 0, Tx.TX_VALUE_SIZE);
		CryptoC.num1.add(CryptoC.num2);
		CryptoC.num1.toByteArrayUnsigned(Wallet.a, (short) 0);

		// get card balance, subtract the pay amount, store in wallet balance

		CryptoC.num1.fromByteArray(Wallet.localBalance, (short) 0, Tx.TX_VALUE_SIZE);
		CryptoC.num2.fromByteArray(Wallet.x, (short) 0, Tx.TX_VALUE_SIZE);
		CryptoC.num1.subtract(CryptoC.num2);
		CryptoC.num1.toByteArrayUnsigned(Wallet.c, (short) 0);
	}

    final static byte[] LOCAL_BALANCE = new byte[]{(byte) 0x0,(byte) 0x0,(byte) 0x0,(byte) 0x0, (byte) 0x05, (byte)0xF5, (byte)0xE1, (byte)0x00}; //100 000 000


}
