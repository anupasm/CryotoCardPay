package com.lapay.agent;

import com.lapay.crypto.ECConfig;
import com.lapay.crypto.ECCurve;
import com.lapay.crypto.ECPoint;
import com.lapay.crypto.OperationSupport;
import com.lapay.crypto.SecP256k1;
import com.lapay.crypto.Integer;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.ECPrivateKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacard.security.Signature;

public class CryptoA {

    public static Integer num1 = null;
    public static Integer num2 = null;

    public static MessageDigest sha256 = null;
    public static MessageDigest ripemd160 = null;

    private static ECConfig ecc = null;
    private static ECCurve curve = null;

    public static ECPrivateKey fundKey = null;
    public static ECPoint fundPointSC = null;

    public static ECPoint comPointLocal = null; // randomly generate, includes the private key

    public static ECPoint baseRevPointRemote = null; // given by remote
    public static byte[] revPointLocal = new byte[33];

    private static Signature signature;

    public static byte[] preimage;
    public static byte[] payhash;
    public static byte[] txPreimage;

    public static void init() {
        OperationSupport.getInstance().setCard(OperationSupport.SIMULATOR);

        try {
            ecc = new ECConfig((short) 256);
            curve = new ECCurve(false, SecP256k1.p, SecP256k1.a, SecP256k1.b, SecP256k1.G, SecP256k1.r);

            // tempory usage for arithmatic
            num1 = new Integer((short) 8, ecc.bnh);
            num2 = new Integer((short) 8, ecc.bnh);

            // base point
            baseRevPointRemote = new ECPoint(curve, ecc.ech);
            baseRevPointRemote.setW(BASE_TEST_VALUE, (short) 0, (short) BASE_TEST_VALUE.length);

            // local funding key
            fundKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, (short) 256, false);
            SecP256k1.setCurveParameters(fundKey);
            fundKey.setS(PAY_REMOTE_TEST_VALUE, (short) 0, (short) 32);

            fundPointSC = new ECPoint(curve, ecc.ech);
            fundPointSC.setW(SC_FUNDING_PK, (short) 0, (short) SC_FUNDING_PK.length);

            sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);

            ripemd160 = MessageDigest.getInstance(MessageDigest.ALG_RIPEMD160, false);

            signature = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);

            preimage = PREIMAGE_TEST_VALUE;// new byte[H256_SIZE];
            payhash = new byte[H160_SIZE];
            txPreimage = new byte[H256_SIZE];

        } catch (CryptoException e) {
            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }

    }

    public static void newPreimage() {

        // RandomData random = RandomData.getInstance(RandomData.ALG_KEYGENERATION);
        // random.nextBytes(preimage, (short) 0, (short) H256_SIZE);
    }

    public static void setRevKey() {

        comPointLocal = new ECPoint(curve, ecc.ech);
        comPointLocal.setW(COMMIT_POINT_TEST_VALUE, (short) 0, (short) COMMIT_POINT_TEST_VALUE.length);

        byte[] data = JCSystem.makeTransientByteArray((short) 65, JCSystem.CLEAR_ON_RESET);
        comPointLocal.encode(data, (short) 0);
        // |0 com 32|
        sha256.update(data, (short) 0, (short) 33);
        baseRevPointRemote.encode(data, (short) 0);
        // |0 base 32|
        sha256.doFinal(data, (short) 0, (short) 33, data, (short) 33);
        // |0 base 32|33 comT 64|
        sha256.reset();
        sha256.update(data, (short) 0, (short) 33);
        comPointLocal.encode(data, (short) 0);
        // |0 com 32|33 comT 64|
        sha256.doFinal(data, (short) 0, (short) 33, data, (short) 0);
        // |0 baseT 31|32|33 comT 64|

        baseRevPointRemote.multiplication(data, (short) 0, (short) 32);

        comPointLocal.multiplication(data, (short) 33, (short) 32);

        comPointLocal.add(baseRevPointRemote);
        comPointLocal.encode(revPointLocal, (short) 0);
    }

    public static byte[] getPK() {
        byte[] buf = new byte[100];
        KeyAgreement keyAgreement = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY, false);
        keyAgreement.init(fundKey);
        short lenPk = keyAgreement.generateSecret(SecP256k1.G, (short) 0, (short) SecP256k1.G.length, buf, (short) 0);
        byte[] bPK = new byte[lenPk];
        Util.arrayCopy(buf, (short) 0, bPK, (short) 0, lenPk);
        return bPK;

    }

    public static byte[] sign(byte[] tx) {
        byte[] sig = new byte[100];
        signature.init(fundKey, Signature.MODE_SIGN);
        short sigLen = signature.signPreComputedHash(tx, (short) 0, CryptoA.H256_SIZE, sig, (short) 0);
        byte[] sigT = new byte[sigLen];
        Util.arrayCopy(sig, (short) 0, sigT, (short) 0, sigLen);
        return sigT;
    }

    public static boolean verify(byte[] txHash, byte[] sig) {
        signature.init(fundPointSC.asPublicKey(), Signature.MODE_VERIFY);

        boolean isVerified = signature.verifyPreComputedHash(txHash, (short) 0, (short) txHash.length, sig,
                (short) 0, (short) sig.length);
        return isVerified;

    }

    final static short PK_SIZE = 33;
    final static short POINT_SIZE = 33;
    final static short SIG_SIZE = 33;
    final static short H160_SIZE = 20;
    final static short H256_SIZE = 32;

    final static byte[] SC_FUNDING_PK = { (byte) 0x04, (byte) 0xc7, (byte) 0xfa, (byte) 0xbe, (byte) 0x05, (byte) 0x18,
            (byte) 0x5a, (byte) 0x29, (byte) 0x89, (byte) 0xa0, (byte) 0x5a, (byte) 0x17, (byte) 0x7f, (byte) 0x17,
            (byte) 0xac, (byte) 0x52, (byte) 0x4f, (byte) 0x43, (byte) 0xf8, (byte) 0xce, (byte) 0xb1, (byte) 0x4a,
            (byte) 0x33, (byte) 0xd0, (byte) 0xb3, (byte) 0xf6, (byte) 0x09, (byte) 0x52, (byte) 0x2d, (byte) 0x4b,
            (byte) 0xbb, (byte) 0xe1, (byte) 0xfc, (byte) 0x1e, (byte) 0x70, (byte) 0xeb, (byte) 0x62, (byte) 0x06,
            (byte) 0x0e, (byte) 0xc7, (byte) 0xbe, (byte) 0xc1, (byte) 0xa0, (byte) 0x6a, (byte) 0x92, (byte) 0x4a,
            (byte) 0xa3, (byte) 0x6d, (byte) 0x3d, (byte) 0xf4, (byte) 0x0d, (byte) 0xda, (byte) 0xca, (byte) 0xd8,
            (byte) 0x6c, (byte) 0xbb, (byte) 0xf1, (byte) 0x25, (byte) 0xcd, (byte) 0x96, (byte) 0x5b, (byte) 0xc8,
            (byte) 0x87, (byte) 0x49, (byte) 0x0e };

    final static byte[] PAY_LOCAL_TEST_VALUE = { (byte) 0x04, (byte) 0x9a, (byte) 0xed, (byte) 0xc3, (byte) 0x3d,
            (byte) 0x37, (byte) 0x07, (byte) 0x7a, (byte) 0x28, (byte) 0x68, (byte) 0xae, (byte) 0xbb, (byte) 0x46,
            (byte) 0x6d, (byte) 0x71, (byte) 0xea, (byte) 0xa8, (byte) 0x4a, (byte) 0xb2, (byte) 0x8c, (byte) 0xe9,
            (byte) 0x11, (byte) 0x36, (byte) 0x93, (byte) 0x0c, (byte) 0xbb, (byte) 0xfe, (byte) 0x2f, (byte) 0x17,
            (byte) 0x68, (byte) 0x1b, (byte) 0xb3, (byte) 0x67, (byte) 0xad, (byte) 0x00, (byte) 0xac, (byte) 0x04,
            (byte) 0xcb, (byte) 0x82, (byte) 0xc3, (byte) 0x77, (byte) 0x36, (byte) 0xac, (byte) 0xba, (byte) 0xdd,
            (byte) 0x38, (byte) 0xc6, (byte) 0x48, (byte) 0xe9, (byte) 0x66, (byte) 0x2d, (byte) 0x57, (byte) 0xe2,
            (byte) 0x76, (byte) 0x56, (byte) 0xfd, (byte) 0xb8, (byte) 0xef, (byte) 0xa2, (byte) 0x7f, (byte) 0x57,
            (byte) 0x35, (byte) 0x5f, (byte) 0xaa, (byte) 0x60 };

    final static byte[] PAY_REMOTE_TEST_VALUE = { (byte) 0x04, (byte) 0x9a, (byte) 0xed, (byte) 0xc3, (byte) 0x3d,
            (byte) 0x37, (byte) 0x07, (byte) 0x7a, (byte) 0x28, (byte) 0x68, (byte) 0xae, (byte) 0xbb, (byte) 0x46,
            (byte) 0x6d, (byte) 0x71, (byte) 0xea, (byte) 0xa8, (byte) 0x4a, (byte) 0xb2, (byte) 0x8c, (byte) 0xe9,
            (byte) 0x11, (byte) 0x36, (byte) 0x93, (byte) 0x0c, (byte) 0xbb, (byte) 0xfe, (byte) 0x2f, (byte) 0x17,
            (byte) 0x69, (byte) 0x1b, (byte) 0xb3, (byte) 0x67, (byte) 0xad, (byte) 0x00, (byte) 0xac, (byte) 0x04,
            (byte) 0xcb, (byte) 0x82, (byte) 0xc3, (byte) 0x77, (byte) 0x36, (byte) 0xac, (byte) 0xba, (byte) 0xdd,
            (byte) 0x38, (byte) 0xc6, (byte) 0x48, (byte) 0xe9, (byte) 0x66, (byte) 0x2d, (byte) 0x57, (byte) 0xe2,
            (byte) 0x76, (byte) 0x56, (byte) 0xfd, (byte) 0xb8, (byte) 0xef, (byte) 0xa2, (byte) 0x7f, (byte) 0x57,
            (byte) 0x35, (byte) 0x5f, (byte) 0xaa, (byte) 0x60 };

    final static byte[] COMMIT_TEST_VALUE = { (byte) 0x04, (byte) 0x9a, (byte) 0xed, (byte) 0xc3, (byte) 0x3d,
            (byte) 0x37, (byte) 0x07, (byte) 0x7a, (byte) 0x28, (byte) 0x68, (byte) 0xae, (byte) 0xbb, (byte) 0x46,
            (byte) 0x6d, (byte) 0x71, (byte) 0xea, (byte) 0xa8, (byte) 0x4a, (byte) 0xb2, (byte) 0x8c, (byte) 0xe9,
            (byte) 0x11, (byte) 0x36, (byte) 0x93, (byte) 0x0c, (byte) 0xbb, (byte) 0xfe, (byte) 0x2f, (byte) 0x17,
            (byte) 0x68, (byte) 0x1b, (byte) 0xb3, (byte) 0x67, (byte) 0xad, (byte) 0x00, (byte) 0xac, (byte) 0x04,
            (byte) 0xcb, (byte) 0x82, (byte) 0xc3, (byte) 0x77, (byte) 0x36, (byte) 0xac, (byte) 0xba, (byte) 0xdd,
            (byte) 0x38, (byte) 0xc6, (byte) 0x48, (byte) 0xe9, (byte) 0x66, (byte) 0x2d, (byte) 0x57, (byte) 0xe2,
            (byte) 0x76, (byte) 0x56, (byte) 0xfd, (byte) 0xb8, (byte) 0xef, (byte) 0xa2, (byte) 0x7f, (byte) 0x57,
            (byte) 0x35, (byte) 0x5f, (byte) 0xaa, (byte) 0x60 };

    final static byte[] BASE_TEST_VALUE = { (byte) 0x04, (byte) 0x9a, (byte) 0xed, (byte) 0xc3, (byte) 0x3d,
            (byte) 0x37, (byte) 0x07, (byte) 0x7a, (byte) 0x28, (byte) 0x68, (byte) 0xae, (byte) 0xbb, (byte) 0x46,
            (byte) 0x6d, (byte) 0x71, (byte) 0xea, (byte) 0xa8, (byte) 0x4a, (byte) 0xb2, (byte) 0x8c, (byte) 0xe9,
            (byte) 0x11, (byte) 0x36, (byte) 0x93, (byte) 0x0c, (byte) 0xbb, (byte) 0xfe, (byte) 0x2f, (byte) 0x17,
            (byte) 0x68, (byte) 0x1b, (byte) 0xb3, (byte) 0x67, (byte) 0xad, (byte) 0x00, (byte) 0xac, (byte) 0x04,
            (byte) 0xcb, (byte) 0x82, (byte) 0xc3, (byte) 0x77, (byte) 0x36, (byte) 0xac, (byte) 0xba, (byte) 0xdd,
            (byte) 0x38, (byte) 0xc6, (byte) 0x48, (byte) 0xe9, (byte) 0x66, (byte) 0x2d, (byte) 0x57, (byte) 0xe2,
            (byte) 0x76, (byte) 0x56, (byte) 0xfd, (byte) 0xb8, (byte) 0xef, (byte) 0xa2, (byte) 0x7f, (byte) 0x57,
            (byte) 0x35, (byte) 0x5f, (byte) 0xaa, (byte) 0x60 };

    final static byte[] COMMIT_POINT_TEST_VALUE = { (byte) 0x04, (byte) 0x9a, (byte) 0xed, (byte) 0xc3, (byte) 0x3d,
            (byte) 0x37, (byte) 0x07, (byte) 0x7a, (byte) 0x28, (byte) 0x68, (byte) 0xae, (byte) 0xbb, (byte) 0x46,
            (byte) 0x6d, (byte) 0x71, (byte) 0xea, (byte) 0xa8, (byte) 0x4a, (byte) 0xb2, (byte) 0x8c, (byte) 0xe9,
            (byte) 0x11, (byte) 0x36, (byte) 0x93, (byte) 0x0c, (byte) 0xbb, (byte) 0xfe, (byte) 0x2f, (byte) 0x17,
            (byte) 0x68, (byte) 0x1b, (byte) 0xb3, (byte) 0x67, (byte) 0xad, (byte) 0x00, (byte) 0xac, (byte) 0x04,
            (byte) 0xcb, (byte) 0x82, (byte) 0xc3, (byte) 0x77, (byte) 0x36, (byte) 0xac, (byte) 0xba, (byte) 0xdd,
            (byte) 0x38, (byte) 0xc6, (byte) 0x48, (byte) 0xe9, (byte) 0x66, (byte) 0x2d, (byte) 0x57, (byte) 0xe2,
            (byte) 0x76, (byte) 0x56, (byte) 0xfd, (byte) 0xb8, (byte) 0xef, (byte) 0xa2, (byte) 0x7f, (byte) 0x57,
            (byte) 0x35, (byte) 0x5f, (byte) 0xaa, (byte) 0x60 };

    final static byte[] PREIMAGE_TEST_VALUE = {
            (byte) 0x37, (byte) 0x07, (byte) 0x7a, (byte) 0x28, (byte) 0x68, (byte) 0xae, (byte) 0xbb, (byte) 0x46,
            (byte) 0x6d, (byte) 0x71, (byte) 0xea, (byte) 0xa8, (byte) 0x4a, (byte) 0xb2, (byte) 0x8c, (byte) 0xe9,
            (byte) 0x11, (byte) 0x36, (byte) 0x93, (byte) 0x0c, (byte) 0xbb, (byte) 0xfe, (byte) 0x2f, (byte) 0x17,
            (byte) 0x68, (byte) 0x1b, (byte) 0xb3, (byte) 0x67, (byte) 0xad, (byte) 0x00, (byte) 0xac, (byte) 0x04,
    };

}