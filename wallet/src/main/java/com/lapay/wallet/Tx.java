package com.lapay.wallet;

public class Tx {
    public static byte[] toLocalScript;
    public static byte[] toRemoteScriptHash;
    public static byte[] toHTLCScriptCard;
    public static byte[] toHTLCScriptAgent;
    public static byte[] tx;
    public static byte[] txToLocalAgentScriptHash;
    public static byte[] txToRemoteAgentScriptHash;
    public static byte[] txToRemoteCardScriptHash;
    public static byte[] txRest;


    public static short SCRIPTHASH_SIZE = 32; // 0x22
    public static byte[] SCRIPTHASH_SIZE_BYTE = new byte[]{0x20}; // todo: append 3

    public static short LOCAL_SCRIPT_REV_START = 2;

    public static short LOCAL_SCRIPT_LOCAL_POINT_START = 42;

    public static short REMOTE_SCRIPT_REMOTE_POINT_START = 1;

    public static short HTLC_SCRIPT_REV_START = 3;
    public static short HTLC_SCRIPT_CARD_PAYHASH_START = 72;
    public static short HTLC_SCRIPT_AGENT_PAYHASH_START = 37;

    public static short TX_LOCAL_SCRIPT_VALUE = 47;
    public static short TX_LOCAL_SCRIPT_START = 56;
    public static short TX_REMOTE_SCRIPT_VALUE = 90;
    public static short TX_REMOTE_SCRIPT_START = 99;
    public static short TX_HTLC_SCRIPT_VALUE = 133;
    public static short TX_HTLC_SCRIPT_START = 142;

    public static short TX_VALUE_SIZE = 8;

    public static void init() {

        toLocalScript = new byte[] { (byte) 0x63, (byte) 0x21,
                // revocation key starts default: agent
                (byte) 0x03, (byte) 0x95, (byte) 0xa7, (byte) 0x06, (byte) 0x37, (byte) 0x1b, (byte) 0x1d, (byte) 0xec,
                (byte) 0x47, (byte) 0x85, (byte) 0xe4, (byte) 0x5b, (byte) 0x65, (byte) 0xb8, (byte) 0xac, (byte) 0x29,
                (byte) 0x25, (byte) 0x45, (byte) 0xb0, (byte) 0x2f, (byte) 0xd8, (byte) 0x2a, (byte) 0xe3, (byte) 0x86,
                (byte) 0xa2, (byte) 0xdc, (byte) 0x18, (byte) 0xb2, (byte) 0xc7, (byte) 0xd3, (byte) 0xf0, (byte) 0x64,
                (byte) 0x97,
                // revocation key ends
                (byte) 0x67, (byte) 0x02, (byte) 0xe8, (byte) 0x03, (byte) 0xb2, (byte) 0x75, (byte) 0x21,
                // local key starts default: card
                (byte) 0x03, (byte) 0xfb, (byte) 0xb8, (byte) 0x6f, (byte) 0xae, (byte) 0x76, (byte) 0x07, (byte) 0x81,
                (byte) 0x14, (byte) 0x5e, (byte) 0x70, (byte) 0x45, (byte) 0x99, (byte) 0x4e, (byte) 0x4e, (byte) 0xa6,
                (byte) 0x76, (byte) 0x54, (byte) 0x1b, (byte) 0x39, (byte) 0x6b, (byte) 0x48, (byte) 0x19, (byte) 0xa9,
                (byte) 0xa9, (byte) 0x65, (byte) 0x19, (byte) 0x76, (byte) 0xce, (byte) 0x22, (byte) 0x88, (byte) 0xab,
                (byte) 0xd5,
                // local key ends
                (byte) 0x68, (byte) 0xac
        };

        toRemoteScriptHash = new byte[] {
                (byte) 0x21,
                // remote key starts
                (byte) 0x03, (byte) 0x82, (byte) 0xbc, (byte) 0xda, (byte) 0xe9, (byte) 0x7f, (byte) 0xa6, (byte) 0x4d,
                (byte) 0x52, (byte) 0x61, (byte) 0x2d, (byte) 0x29, (byte) 0xa0, (byte) 0x09, (byte) 0x2e, (byte) 0x60,
                (byte) 0x3e, (byte) 0xef, (byte) 0xb0, (byte) 0x0c, (byte) 0x44, (byte) 0x65, (byte) 0x7a, (byte) 0x20,
                (byte) 0x98, (byte) 0x74, (byte) 0xb0, (byte) 0xad, (byte) 0xe8, (byte) 0x77, (byte) 0xf9, (byte) 0x75,
                (byte) 0x25,
                // remote key ends
                (byte) 0xad
        };

        toHTLCScriptCard = new byte[] {
                (byte) 0x76, (byte) 0xa9, (byte) 0x14,
                // rev key starts default card
                (byte) 0x7c, (byte) 0x65, (byte) 0x0e, (byte) 0x70, (byte) 0x35, (byte) 0x3e, (byte) 0xb2, (byte) 0x2d,
                (byte) 0x0f, (byte) 0xdd, (byte) 0x58, (byte) 0xa6, (byte) 0x0f, (byte) 0x86, (byte) 0xa8, (byte) 0xc2,
                (byte) 0xb7, (byte) 0x83, (byte) 0xdb, (byte) 0xa3,
                // rev keys ends
                (byte) 0x87, (byte) 0x64, (byte) 0x82, (byte) 0x01, (byte) 0x20, (byte) 0x87, (byte) 0x64, (byte) 0x02,
                (byte) 0xe8, (byte) 0x03, (byte) 0xb2, (byte) 0x75, (byte) 0x21, (byte) 0x03, (byte) 0xd1, (byte) 0x83,
                (byte) 0x34, (byte) 0xa2, (byte) 0xfa, (byte) 0xd2, (byte) 0x9f, (byte) 0x67, (byte) 0xf8, (byte) 0xc4,
                (byte) 0xbb, (byte) 0xd0, (byte) 0xe5, (byte) 0x46, (byte) 0xaf, (byte) 0x88, (byte) 0x77, (byte) 0x1c,
                (byte) 0x91, (byte) 0xaf, (byte) 0x54, (byte) 0x56, (byte) 0x54, (byte) 0xe2, (byte) 0x4a, (byte) 0x0b,
                (byte) 0x17, (byte) 0x81, (byte) 0x4d, (byte) 0x78, (byte) 0xf8, (byte) 0x9b, (byte) 0x67, (byte) 0xa9,
                (byte) 0x14,

                // payhash starts
                (byte) 0x98, (byte) 0x56, (byte) 0xb3, (byte) 0x03, (byte) 0x4d, (byte) 0x98, (byte) 0x73, (byte) 0xd8,
                (byte) 0x63, (byte) 0xc8, (byte) 0x0e, (byte) 0xad, (byte) 0x73, (byte) 0xdc, (byte) 0x9e, (byte) 0xdf,
                (byte) 0x9b, (byte) 0x3f, (byte) 0xba, (byte) 0x43,
                // payhash ends

                (byte) 0x88, (byte) 0x21, (byte) 0x02, (byte) 0xd5, (byte) 0xcb, (byte) 0xc5, (byte) 0xe3, (byte) 0x96,
                (byte) 0xe7, (byte) 0xfd, (byte) 0x4f, (byte) 0x39, (byte) 0xed, (byte) 0x99, (byte) 0xe2, (byte) 0x7a,
                (byte) 0x1b, (byte) 0x99, (byte) 0x69, (byte) 0xcd, (byte) 0x2d, (byte) 0x52, (byte) 0x46, (byte) 0xed,
                (byte) 0x21, (byte) 0x6e, (byte) 0xeb, (byte) 0x93, (byte) 0xc5, (byte) 0x7e, (byte) 0x1b, (byte) 0xe8,
                (byte) 0xbe, (byte) 0xf0, (byte) 0xb6, (byte) 0x68, (byte) 0x68, (byte) 0xac };

        toHTLCScriptAgent = new byte[] {
                (byte) 0x76, (byte) 0xa9, (byte) 0x14,
                // rev key starts default  agent
                (byte) 0x7c, (byte) 0x65, (byte) 0x0e, (byte) 0x70, (byte) 0x35, (byte) 0x3e, (byte) 0xb2, (byte) 0x2d,
                (byte) 0x0f, (byte) 0xdd, (byte) 0x58, (byte) 0xa6, (byte) 0x0f, (byte) 0x86, (byte) 0xa8, (byte) 0xc2,
                (byte) 0xb7, (byte) 0x83, (byte) 0xdb, (byte) 0xa3,
                // rev key ends
                (byte) 0x87, (byte) 0x64, (byte) 0x82, (byte) 0x01, (byte) 0x20, (byte) 0x87, (byte) 0x63, (byte) 0x02,
                (byte) 0xe8, (byte) 0x03, (byte) 0xb2, (byte) 0x75, (byte) 0xa9, (byte) 0x14,

                // payhash starts
                (byte) 0x98, (byte) 0x56, (byte) 0xb3, (byte) 0x03, (byte) 0x4d, (byte) 0x98, (byte) 0x73, (byte) 0xd8,
                (byte) 0x63, (byte) 0xc8, (byte) 0x0e, (byte) 0xad, (byte) 0x73, (byte) 0xdc, (byte) 0x9e, (byte) 0xdf,
                (byte) 0x9b, (byte) 0x3f, (byte) 0xba, (byte) 0x43,
                // payhash ends

                (byte) 0x88, (byte) 0x21, (byte) 0x02, (byte) 0xd5, (byte) 0xcb, (byte) 0xc5, (byte) 0xe3, (byte) 0x96,
                (byte) 0xe7, (byte) 0xfd, (byte) 0x4f, (byte) 0x39, (byte) 0xed, (byte) 0x99, (byte) 0xe2, (byte) 0x7a,
                (byte) 0x1b, (byte) 0x99, (byte) 0x69, (byte) 0xcd, (byte) 0x2d, (byte) 0x52, (byte) 0x46, (byte) 0xed,
                (byte) 0x21, (byte) 0x6e, (byte) 0xeb, (byte) 0x93, (byte) 0xc5, (byte) 0x7e, (byte) 0x1b, (byte) 0xe8,
                (byte) 0xbe, (byte) 0xf0, (byte) 0xb6, (byte) 0x67, (byte) 0x02, (byte) 0xd0, (byte) 0x07, (byte) 0xb2,
                (byte) 0x75, (byte) 0x21, (byte) 0x03, (byte) 0xd1, (byte) 0x83, (byte) 0x34, (byte) 0xa2, (byte) 0xfa,
                (byte) 0xd2, (byte) 0x9f, (byte) 0x67, (byte) 0xf8, (byte) 0xc4, (byte) 0xbb, (byte) 0xd0, (byte) 0xe5,
                (byte) 0x46, (byte) 0xaf, (byte) 0x88, (byte) 0x77, (byte) 0x1c, (byte) 0x91, (byte) 0xaf, (byte) 0x54,
                (byte) 0x56, (byte) 0x54, (byte) 0xe2, (byte) 0x4a, (byte) 0x0b, (byte) 0x17, (byte) 0x81, (byte) 0x4d,
                (byte) 0x78, (byte) 0xf8, (byte) 0x9b, (byte) 0x68, (byte) 0x68, (byte) 0xac };

        tx = new byte[] {
                (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x00,

                (byte) 0x01, // # inputs

                (byte) 0x35, (byte) 0x13, (byte) 0x70,
                (byte) 0x29, (byte) 0x6b, (byte) 0x1e, (byte) 0x6b, (byte) 0xfe, (byte) 0x19, (byte) 0x98, (byte) 0xa7,
                (byte) 0x3b, (byte) 0x3b, (byte) 0x21, (byte) 0x6a, (byte) 0xff, (byte) 0x01, (byte) 0xe0, (byte) 0x26,
                (byte) 0x70, (byte) 0xb7, (byte) 0x86, (byte) 0x71, (byte) 0x05, (byte) 0x55, (byte) 0x96, (byte) 0x50,
                (byte) 0x01, (byte) 0x04, (byte) 0xb8, (byte) 0x65, (byte) 0x1b, // in tx id

                (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x00, // out index

                (byte) 0x00, // sig size

                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, // locktime

                (byte) 0x03, // # outputs
        };

        //to local value
        //to local script size
        txToLocalAgentScriptHash = new byte[]{

                // to self script hash from agent
                (byte) 0x00, (byte) 0x20, (byte) 0x74, (byte) 0x72, (byte) 0x2d, (byte) 0xe1, (byte) 0x12, (byte) 0x58,
                (byte) 0x30, (byte) 0x8f, (byte) 0x3c, (byte) 0xab, (byte) 0x35, (byte) 0xb4, (byte) 0x80, (byte) 0x64,
                (byte) 0x25, (byte) 0x58, (byte) 0x99, (byte) 0x95, (byte) 0x1e, (byte) 0x5e, (byte) 0xa6, (byte) 0x45,
                (byte) 0x07, (byte) 0x79, (byte) 0xf7, (byte) 0x15, (byte) 0xe0, (byte) 0x86, (byte) 0x9b, (byte) 0x6f,
                (byte) 0x6e, (byte) 0x4c,

        };


        //to remote value
        //to remote script size

        txToRemoteAgentScriptHash = new byte[]{
                // to card script hash from agent 
                (byte) 0x00, (byte) 0x20, (byte) 0xb0, (byte) 0x42, (byte) 0x3e, (byte) 0xb5, (byte) 0xce, (byte) 0x31,
                (byte) 0xfe, (byte) 0x60, (byte) 0xaa, (byte) 0x63, (byte) 0x67, (byte) 0x1d, (byte) 0xcd, (byte) 0x2e,
                (byte) 0x0c, (byte) 0x00, (byte) 0x1f, (byte) 0xa9, (byte) 0xb4, (byte) 0x3f, (byte) 0x08, (byte) 0x2b,
                (byte) 0xb4, (byte) 0x0a, (byte) 0xe1, (byte) 0xd8, (byte) 0xfc, (byte) 0xaf, (byte) 0x83, (byte) 0x87,
                (byte) 0x9d, (byte) 0xf0,

        };

        //to htlc value
        //to htlc script size
        //to htlc script hash
        
        //lock time + sighash all
        txRest = new byte[]{
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00
        };


        
        txToRemoteCardScriptHash = new byte[]{
            // to remote script hash from card
            (byte) 0x00, (byte) 0x20, (byte) 0xb0, (byte) 0x42, (byte) 0x3e, (byte) 0xb5, (byte) 0xce, (byte) 0x31,
            (byte) 0xfe, (byte) 0x60, (byte) 0xaa, (byte) 0x63, (byte) 0x67, (byte) 0x1d, (byte) 0xcd, (byte) 0x2e,
            (byte) 0x0c, (byte) 0x00, (byte) 0x1f, (byte) 0xa9, (byte) 0xb4, (byte) 0x3f, (byte) 0x08, (byte) 0x2b,
            (byte) 0xb4, (byte) 0x0a, (byte) 0xe1, (byte) 0xd8, (byte) 0xfc, (byte) 0xaf, (byte) 0x83, (byte) 0x87,
            (byte) 0x9d, (byte) 0xf0,

    };

    }
}
