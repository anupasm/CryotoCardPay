package com.lapay.wallet;

import java.nio.ByteBuffer;
import java.util.Arrays;

import javacard.framework.AID;
import org.junit.Before;
import org.junit.Test;

import com.lapay.agent.Agent;
import com.licel.jcardsim.base.Simulator;

public class CardTest {
	Simulator simulator;
	static final byte[] bAid = new byte[] { (byte) 0xd2, 0x76, 0x00, (byte) 0xFF, (byte) 0xFE, 0x01, 0x02, 0x03, 0x04,
			0x05 };
	static final AID aid = new AID(bAid, (short) 0, (byte) bAid.length);
	static final byte[] success = { (byte) 0x90, 0x00 };
	static final byte[] securityNotSatisfied = { 0x69, (byte) 0x82 };

	Agent agent;

	@Before
	public void setup() {
		byte[] params = new byte[bAid.length + 1];
		params[0] = (byte) bAid.length;
		System.arraycopy(bAid, 0, params, 1, bAid.length);

		simulator = new Simulator();
		simulator.resetRuntime();
		simulator.installApplet(aid, Card.class, params, (short) 0, (byte) params.length);
		simulator.selectApplet(aid);
		agent = new Agent();
	}


	@Test
	public void testPay() {
	
		// payment amount
		byte[] amount = new byte[]{(byte)0x0, (byte)0x0, (byte)0x0, (byte)0x0, (byte)0x0, (byte)0x0, (byte)0x27, (byte)0x10};//10000


		/* POS to SMARTCARD: Invoice */

		// invoice command
		byte[] invoiceCommand = new byte[]{
			(byte)0x0, //CLA
			INVOICE, //command
			(byte)0x00, (byte)0x00,  //not used
			(byte)amount.length, //length
		};
		invoiceCommand = concat(invoiceCommand, amount);

		dumpHex("Invoice Command |cmd|size|amount|",invoiceCommand);
		byte[] resp = simulator.transmitCommand(invoiceCommand);

		// smartcard's response with pay hash and signature for agent (|)
		dumpHex("Invoice Command Response |sigLen| sig|hash|", resp);

		//signature length extract
		short sigLen = ByteBuffer.wrap(resp, 0, 2).getShort();
		//signature extract
		byte[] sig = Arrays.copyOfRange(resp, 2, sigLen+2);
		//hash extract
		byte[] hash = Arrays.copyOfRange(resp, sigLen+2, sigLen+22);

		/* POS to AGENT: Pre-Commitment of SC */

		//send hash and sig to agent for verification
		byte[] agentSig = agent.commit(amount, sig, hash);
	
		// receives agent pre-commitment sig from agent
		dumpHex("Agent Verification and Pre-Commitment Signature ", agentSig);


		/* POS to SMARTCARD: Verify Pre-Commitment of Agent */

		byte[] verifyCommand = new byte[]{
			(byte)0x0, //CLA
			AGENT_COMMIT_VERIFY, //command
			(byte)0x00, (byte)0x00,  //not used
			(byte)agentSig.length, //sig length
		};
		verifyCommand = concat(verifyCommand, agentSig);

		dumpHex("Verify Agent's Signature |cmd 4|size 1|sig|", verifyCommand);
		resp = simulator.transmitCommand(verifyCommand);

		if(Arrays.equals(resp,success)){
			dumpHex("Smartcard Verification Success", resp);
		}else{
			dumpHex("Smartcard Verification Failed", resp);
		}

		//.... PAYMENT ROUTING BEGINS


		/* POS to SMARTCARD: Reveal request with payhash */

		byte[] revealCommand = new byte[]{
			(byte)0x0, //CLA
			REVEAL_REQUEST, //command
			(byte)0x00, (byte)0x00,  //not used
			(byte)hash.length, //sig length
		};
		revealCommand = concat(revealCommand, hash);
		byte[] preimage = simulator.transmitCommand(revealCommand);
		dumpHex("Revealed Pre-Image", preimage);
	}

	@Test //@Ignore
	public void testExtractPK() {
		byte[] command = new byte[]{
			(byte)0x0, //CLA
			EXTRACT_PK, //command
			(byte)0x00, (byte)0x00,  //not used
		};

		dumpHex("Extract SC PK Cmd", command);
		byte[] scPK = simulator.transmitCommand(command);
		dumpHex("SC PK", scPK);

		byte[] agentPk = agent.getPK();
		dumpHex("AGENT PK", agentPk);
	}

	@SuppressWarnings("unused")
	private void dumpHex(String title,byte[] data) {
		String out =title+"\n";
		for (byte b : data) {
			out += String.format("%02x ", b);
		}
		System.out.println(out);
	}

	public static byte[] concat(byte[] a, byte[] b) {
		int lenA = a.length;
		int lenB = b.length;
		byte[] c = Arrays.copyOf(a, lenA + lenB);
		System.arraycopy(b, 0, c, lenA, lenB);
		return c;
	}

	final static byte INVOICE = (byte) 0x20;
	final static byte AGENT_COMMIT_VERIFY = (byte) 0x50;
	final static byte REVEAL_REQUEST = (byte) 0x70;
	final static byte EXTRACT_PK = (byte) 0x90;

}