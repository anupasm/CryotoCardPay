package com.lapay.wallet;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

public class Card extends Applet {

	public static void install(byte[] bArray, short bOffset, byte bLength) {
		// GP-compliant JavaCard applet registration
		new Card().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
	}

	public Card() {
		CryptoC.init();
		Tx.init();
		Wallet.init();
	}

	public void process(APDU apdu) {
		if (selectingApplet()) {
			return; // 0x9000
		}

		byte[] buf = apdu.getBuffer();
		if (buf[ISO7816.OFFSET_CLA] != ISO7816.CLA_ISO7816) {
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}

		switch (buf[ISO7816.OFFSET_INS]) {

			case INVOICE: {

				// INPUT:
				// |CMD 4| LEN 8 | Amount 8|

				// copy invoice pay amount to local storage Wallet.payAmount
				Wallet.updatePayAmount(buf);


				// ------ HTLC SCRIPT HASH ------
				// Not to mix up with tx build
				CryptoC.newPreimage(); // generate new preimage and store in memory

				// hash256(preimage)
				CryptoC.sha256.reset();
				CryptoC.sha256.doFinal(CryptoC.preimage, (short) 0, CryptoC.H256_SIZE, buf, (short) 0);

				// hash160(hash256(preimage)); store in tx script for hash generation and store
				// in persistent memory for future usage
				CryptoC.ripemd160.reset();
				CryptoC.ripemd160.doFinal(buf, (short) 0, CryptoC.H256_SIZE, CryptoC.payhash, (short) 0);

				Util.arrayCopy(CryptoC.payhash, (short) 0, Tx.toHTLCScriptAgent, Tx.HTLC_SCRIPT_AGENT_PAYHASH_START,
						CryptoC.H160_SIZE);

				// todo encrypt

				// generate htlc script hash, save in buf
				// |0-31|
				CryptoC.sha256.reset();
				CryptoC.sha256.doFinal(Tx.toHTLCScriptAgent, (short) 0, (short) Tx.toHTLCScriptAgent.length, buf,
						(short) 0);

				// ----- TX PREIMAGE BUILD (Agent's version) ------

				// TX HEADER UDATE
				CryptoC.sha256.reset();
				CryptoC.sha256.update(Tx.tx, (short) 0, (short) Tx.tx.length);

				// TO LOCAL VALUE UPDATE (agent's version)

				CryptoC.sha256.update(Wallet.a, (short) 0, Tx.TX_VALUE_SIZE);

				// TO LOCAL SCRIPT SIZE
				CryptoC.sha256.update(Tx.SCRIPTHASH_SIZE_BYTE, (short) 0, (short) 1);

				// TO LOCAL SCRIPT
				CryptoC.sha256.update(Tx.txToLocalAgentScriptHash, (short) 0, Tx.SCRIPTHASH_SIZE);

				// TO REMOTE VALUE UPDATE (Agent's version)

				CryptoC.sha256.update(Wallet.c, (short) 0, Tx.TX_VALUE_SIZE);

				// TO REMOTE SCRIPT SIZE
				CryptoC.sha256.update(Tx.SCRIPTHASH_SIZE_BYTE, (short) 0, (short) 1);

				// TO REMOTE SCRIPT
				CryptoC.sha256.update(Tx.txToRemoteAgentScriptHash, (short) 0, Tx.SCRIPTHASH_SIZE);

				// TO HTLC VALUE UPDATE
				CryptoC.sha256.update(Wallet.x, (short) 0, Tx.TX_VALUE_SIZE);

				// TO HTLC SCRIPT SIZE
				CryptoC.sha256.update(Tx.SCRIPTHASH_SIZE_BYTE, (short) 0, (short) 1);

				// TO HTLC SCRIPT
				CryptoC.sha256.update(buf, (short) 0, Tx.SCRIPTHASH_SIZE);

				// tx ready -- double hashing
				CryptoC.sha256.doFinal(Tx.txRest, (short) 0, (short) Tx.txRest.length, buf, (short) 0);
				CryptoC.sha256.reset();
				CryptoC.sha256.doFinal(buf, (short) 0, CryptoC.H256_SIZE, buf, (short) 0); // |0-31|
				short sigLen = CryptoC.sign(buf, (short) 0, buf, (short) 2);
				Util.setShort(buf, (short) 0, sigLen);

				// extract payment hash to buf
				Util.arrayCopy(CryptoC.payhash, (short) 0, buf, (short) (sigLen + 2), CryptoC.H160_SIZE);

				apdu.setOutgoingAndSend((short) 0, (short) 100);
				break;
			}
			case (byte)AGENT_COMMIT_VERIFY: {

				short sigLen = buf[4];

				// Set revocation key
				CryptoC.setRevKey();

				// ---- TO LOCAL SCRIPT HASH BUILD

				// copy rev key to tolocal script
				Util.arrayCopy(CryptoC.revPointLocal, (short) 0, Tx.toLocalScript, Tx.LOCAL_SCRIPT_REV_START,
						CryptoC.POINT_SIZE);

				// |begin 4|sigLen 1|sig sigLen|scriptHash 32|
				// generate tolocal script hash, save in to local script hash in buf
				short shOffset = (short) (sigLen + 5);

				CryptoC.sha256.reset();
				CryptoC.sha256.doFinal(Tx.toLocalScript, (short) 0, (short) Tx.toLocalScript.length, buf, shOffset);

				// ---- HTLC SCRIPT HASH BUILD

				// copy rev key to htlc script
				Util.arrayCopy(CryptoC.revPointLocal, (short) 0, Tx.toHTLCScriptCard, Tx.HTLC_SCRIPT_REV_START,
						CryptoC.POINT_SIZE);
				// copy payhash to htlc script
				Util.arrayCopy(CryptoC.payhash, (short) 0, Tx.toHTLCScriptCard, Tx.HTLC_SCRIPT_CARD_PAYHASH_START,
						CryptoC.H160_SIZE);

				// |begin 4|sigLen 1|sig sigLen|scriptHash 32|htlcScriptHash 32|

				// generate htlc script hash, save in buf
				short htlcOffset = (short) (shOffset + CryptoC.H256_SIZE);
				CryptoC.sha256.reset();
				CryptoC.sha256.doFinal(Tx.toHTLCScriptCard, (short) 0, (short) Tx.toHTLCScriptCard.length, buf,
						(short) htlcOffset);

				// ----- TX PREIMAGE BUILD ------

				// TX HEADER UDATE
				CryptoC.sha256.reset();
				CryptoC.sha256.update(Tx.tx, (short) 0, (short) Tx.tx.length);

				// TO LOCAL VALUE UPDATE
				CryptoC.sha256.update(Wallet.c, (short) 0, Tx.TX_VALUE_SIZE);

				// TO LOCAL SCRIPT SIZE
				CryptoC.sha256.update(Tx.SCRIPTHASH_SIZE_BYTE, (short) 0, (short) 1);

				// TO LOCAL SCRIPT
				CryptoC.sha256.update(buf, shOffset, Tx.SCRIPTHASH_SIZE);

				// TO REMOTE VALUE UPDATE
				CryptoC.sha256.update(Wallet.a, (short) 0, Tx.TX_VALUE_SIZE);

				// TO REMOTE SCRIPT SIZE
				CryptoC.sha256.update(Tx.SCRIPTHASH_SIZE_BYTE, (short) 0, (short) 1);

				// TO REMOTE SCRIPT
				CryptoC.sha256.update(Tx.txToRemoteCardScriptHash, (short) 0, Tx.SCRIPTHASH_SIZE);

				// TO HTLC VALUE UPDATE
				CryptoC.sha256.update(Wallet.x, (short) 0, Tx.TX_VALUE_SIZE);

				// TO HTLC SCRIPT SIZE
				CryptoC.sha256.update(Tx.SCRIPTHASH_SIZE_BYTE, (short) 0, (short) 1);

				// TO HTLC SCRIPT
				CryptoC.sha256.update(buf, htlcOffset, Tx.SCRIPTHASH_SIZE);

				// tx ready -- double hashing
				CryptoC.sha256.doFinal(Tx.txRest, (short) 0, (short) Tx.txRest.length, buf, shOffset);
				CryptoC.sha256.reset();
				CryptoC.sha256.doFinal(buf, shOffset, CryptoC.H256_SIZE, buf, shOffset);

				boolean isVerified = CryptoC.verify(buf, (short) 5, sigLen, shOffset, CryptoC.H256_SIZE);
				if (!isVerified) {
					ISOException.throwIt(SW_VERIFICATION_FAILED);
				}
				break;
			}
			case REVEAL_REQUEST: {
				//todo compare
				Util.arrayCopy(CryptoC.preimage, (short)0, buf, (short)0, (short) CryptoC.preimage.length);
				apdu.setOutgoingAndSend((short) 0, (short) CryptoC.preimage.length);
				break;
			}
			case EXTRACT_PK: {
				CryptoC.getPK(buf);
				apdu.setOutgoingAndSend((short) 0, (short) 100);
				break;
			}
			default:
				ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}

	final static byte INVOICE = (byte) 0x20;
	final static byte AGENT_COMMIT_VERIFY = (byte) 0x50;
	final static byte REVEAL_REQUEST = (byte) 0x70;
	final static byte EXTRACT_PK = (byte) 0x90;

	final static short SW_VERIFICATION_FAILED = 0x6300;

}