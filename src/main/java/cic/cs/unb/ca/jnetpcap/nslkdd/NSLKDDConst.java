package cic.cs.unb.ca.jnetpcap.nslkdd;


public class NSLKDDConst {


    /*
     * ICMP type field
     * Values from linux source code used
     * https://github.com/torvalds/linux/blob/master/include/uapi/linux/icmp.h
     */
    public static enum icmp_field_type_t {
        ECHOREPLY, // 0,
                DEST_UNREACH, // 3,
                SOURCE_QUENCH, // 4,
                REDIRECT, // 5,
                ECHO, // 8,
                TIME_EXCEEDED, // 11,
                PARAMETERPROB, // = 12,
                TIMESTAMP, // = 13,
                TIMESTAMPREPLY, // = 14,
                INFO_REQUEST, // = 15,
                INFO_REPLY, // = 16,
                ADDRESS, // = 17,
                ADDRESSREPLY // = 18
    };


    //Protocol Type  PROTO_ZERO = 0, ICMP = 1,	TCP = 6,UDP = 17

    public static int PROTOCOL_TYPE_ZERO  = 0;
    public static int PROTOCOL_TYPE_ICMP  = 1;
    public static int PROTOCOL_TYPE_TCP  = 6;
    public static int PROTOCOL_TYPE_UDP  = 17;
}
