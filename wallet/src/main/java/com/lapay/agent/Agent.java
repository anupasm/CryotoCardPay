package com.lapay.agent;

import javacard.framework.Util;

public class Agent {

	public Agent() {
		CryptoA.init();
		Tx.init();
		Wallet.init();
	}

	public byte[] getPK(){
		return CryptoA.getPK();
	}
	
	public byte[] commit(byte[] payAmount,byte[] scPreCommitSig, byte[] txHash){
		Wallet.updatePayAmount(payAmount);
		if(this.verifySCPreCommit(scPreCommitSig, txHash)){
			CryptoA.setRevKey();
			return this.genPreCommit(txHash);
		}
		return new byte[]{};
	}

	public boolean verifySCPreCommit(byte[] scPreCommitSig, byte[] txHash) {

		Util.arrayCopy(txHash, (short) 0, Tx.toHTLCScriptAgent, Tx.HTLC_SCRIPT_AGENT_PAYHASH_START, CryptoA.H160_SIZE);

		// generate htlc script hash, save in buf
		byte htlcScriptHash[] = new byte[CryptoA.H256_SIZE];
		CryptoA.sha256.reset();
		CryptoA.sha256.doFinal(Tx.toHTLCScriptAgent, (short) 0, (short) Tx.toHTLCScriptAgent.length, htlcScriptHash,
				(short) 0);

		// todo decrypt

		// ----- TX PREIMAGE BUILD (My version)------

		// TX HEADER UDATE
		CryptoA.sha256.reset();
		CryptoA.sha256.update(Tx.tx, (short) 0, (short) Tx.tx.length);

		// TO LOCAL VALUE UPDATE (from wallet)
		CryptoA.sha256.update(Wallet.a, (short) 0, Tx.TX_VALUE_SIZE);

		// TO LOCAL SCRIPT SIZE
		CryptoA.sha256.update(Tx.SCRIPTHASH_SIZE_BYTE, (short) 0, (short) 1);

		// TO LOCAL SCRIPT
		CryptoA.sha256.update(Tx.txToLocalAgentScriptHash, (short) 0, Tx.SCRIPTHASH_SIZE);

		// TO REMOTE VALUE UPDATE
		CryptoA.sha256.update(Wallet.c, (short) 0, Tx.TX_VALUE_SIZE);

		// TO REMOTE SCRIPT SIZE
		CryptoA.sha256.update(Tx.SCRIPTHASH_SIZE_BYTE, (short) 0, (short) 1);

		// TO REMOTE SCRIPT
		CryptoA.sha256.update(Tx.txToRemoteAgentScriptHash, (short) 0, Tx.SCRIPTHASH_SIZE);

		// TO HTLC VALUE UPDATE
		CryptoA.sha256.update(Wallet.x, (short) 0, Tx.TX_VALUE_SIZE);

		// TO HTLC SCRIPT SIZE
		CryptoA.sha256.update(Tx.SCRIPTHASH_SIZE_BYTE, (short) 0, (short) 1);

		// TO HTLC SCRIPT
		CryptoA.sha256.update(htlcScriptHash, (short) 0, Tx.SCRIPTHASH_SIZE);

		// tx ready -- double hashing
		byte[] tx = new byte[CryptoA.H256_SIZE];
		CryptoA.sha256.doFinal(Tx.txRest, (short) 0, (short) Tx.txRest.length, tx, (short) 0);
		CryptoA.sha256.reset();
		CryptoA.sha256.doFinal(tx, (short) 0, (short) 32, tx, (short) 0); // |0-31|

		return CryptoA.verify(tx, scPreCommitSig);
	}

	public byte[] genPreCommit(byte[] payHash) {

		// ---- TO LOCAL SCRIPT HASH BUILD

		// copy rev key to tolocal script
		Util.arrayCopy(CryptoA.revPointLocal, (short) 0, Tx.toLocalScript, Tx.LOCAL_SCRIPT_REV_START,
				CryptoA.POINT_SIZE);

		// generate tolocal script hash of SC, save in to local script hash in tx
		byte[] toLocalScriptHash = new byte[CryptoA.H256_SIZE];
		CryptoA.sha256.reset();
		CryptoA.sha256.doFinal(Tx.toLocalScript, (short) 0, (short) Tx.toLocalScript.length, toLocalScriptHash,
				(short) 0);

		// ---- HTLC SCRIPT HASH BUILD

		// copy rev key to htlc script
		Util.arrayCopy(CryptoA.revPointLocal, (short) 0, Tx.toHTLCScriptCard, Tx.HTLC_SCRIPT_REV_START,
				CryptoA.POINT_SIZE);
		// copy payhash to htlc script
		Util.arrayCopy(payHash, (short) 0, Tx.toHTLCScriptCard, Tx.HTLC_SCRIPT_CARD_PAYHASH_START,
				CryptoA.H160_SIZE);

		// generate htlc script hash, save in toHTLCScriptHash
		byte[] toHTLCScriptHash = new byte[CryptoA.H256_SIZE];
		CryptoA.sha256.reset();
		CryptoA.sha256.doFinal(Tx.toHTLCScriptCard, (short) 0, (short) Tx.toHTLCScriptCard.length, toHTLCScriptHash, (short) 0);

		// ----- TX PREIMAGE BUILD ------

		// TX HEADER UDATE
		CryptoA.sha256.reset();
		CryptoA.sha256.update(Tx.tx, (short) 0, (short) Tx.tx.length);

		// TO LOCAL VALUE UPDATE (SC LOCAL)
		CryptoA.sha256.update(Wallet.c, (short) 0, Tx.TX_VALUE_SIZE);

		// TO LOCAL SCRIPT SIZE
		CryptoA.sha256.update(Tx.SCRIPTHASH_SIZE_BYTE, (short) 0, (short) 1);

		// TO LOCAL SCRIPT
		CryptoA.sha256.update(toLocalScriptHash, (short) 0, Tx.SCRIPTHASH_SIZE);

		// TO REMOTE VALUE UPDATE
		CryptoA.sha256.update(Wallet.a, (short) 0, Tx.TX_VALUE_SIZE);

		// TO REMOTE SCRIPT SIZE
		CryptoA.sha256.update(Tx.SCRIPTHASH_SIZE_BYTE, (short) 0, (short) 1);

		// TO REMOTE SCRIPT
		CryptoA.sha256.update(Tx.txToRemoteCardScriptHash, (short) 0, Tx.SCRIPTHASH_SIZE);

		// TO HTLC VALUE UPDATE
		CryptoA.sha256.update(Wallet.x, (short) 0, Tx.TX_VALUE_SIZE);

		// TO HTLC SCRIPT SIZE
		CryptoA.sha256.update(Tx.SCRIPTHASH_SIZE_BYTE, (short) 0, (short) 1);

		// TO HTLC SCRIPT
		CryptoA.sha256.update(toHTLCScriptHash, (short) 0, Tx.SCRIPTHASH_SIZE);

		// tx ready -- double hashing
		byte[] tx = new byte[CryptoA.H256_SIZE];

		CryptoA.sha256.doFinal(Tx.txRest, (short) 0, (short) Tx.txRest.length, tx, (short) 0);
		CryptoA.sha256.reset();
		CryptoA.sha256.doFinal(tx, (short) 0, CryptoA.H256_SIZE, tx, (short) 0);

		// sign the tx
		// 26 3c cd ad e9 1c 43 02 12 e4 dc c7 03 bb d3 a3 f8 cb 4a 63 2d 44 88 90 31 08 86 ff 70 2b de 3e 
		return CryptoA.sign(tx);
	}

}