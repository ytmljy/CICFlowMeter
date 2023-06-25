package cic.cs.unb.ca.jnetpcap;


public class NSLKDDConst {

    /**
     * Conversatiov states
     *	- INIT & SF for all protocols except TCP
     *	- other states specific to TCP
     * Description from https://www.bro.org/sphinx/scripts/base/protocols/conn/main.bro.html
     */
    public enum conversation_state_t {
        // General states
        INIT,		// Nothing happened yet.
        SF,			// Normal establishment and termination. Note that this is the same
        // symbol as for state S1. You can tell the two apart because for S1 there
        // will not be any byte counts in the summary, while for SF there will be.

        // TCP specific
        S0,			// Connection attempt seen, no reply.
        S1,			// Connection established, not terminated.
        S2,			// Connection established and close attempt by originator seen (but no reply from responder).
        S3,			// Connection established and close attempt by responder seen (but no reply from originator).
        REJ,		// Connection attempt rejected.
        RSTOS0,		// Originator sent a SYN followed by a RST, we never saw a SYN-ACK from the responder.
        RSTO,		// Connection established, originator aborted (sent a RST).
        RSTR,		// Established, responder aborted.
        SH,			// Originator sent a SYN followed by a FIN, we never saw a SYN ACK from the responder (hence the connection was �half� open).
        RSTRH,		// Responder sent a SYN ACK followed by a RST, we never saw a SYN from the (purported) originator.
        SHR,		// Responder sent a SYN ACK followed by a FIN, we never saw a SYN from the originator.
        OTH,		// No SYN seen, just midstream traffic (a �partial connection� that was not later closed).

        // Internal states (TCP-specific)
        ESTAB,		// Established - ACK send by originator in S1 state; externally represented as S1
        S4,			// SYN ACK seen - State between INIT and (RSTRH or SHR); externally represented as OTH
        S2F,		// FIN send by responder in state S2 - waiting for final ACK; externally represented as S2
        S3F			// FIN send by originator in state S3 - waiting for final ACK; externally represented as S3
    };

    /**
     * Services
     * ! order & number of services must be the same in string mapping
     * see Conversation::SERVICE_NAMES[] in Conversation.cpp
     */
    public enum service_t {
        // General
        SRV_OTHER,
        SRV_PRIVATE,

        // ICMP
        SRV_ECR_I,
        SRV_URP_I,
        SRV_URH_I,
        SRV_RED_I,
        SRV_ECO_I,
        SRV_TIM_I,
        SRV_OTH_I,

        // UDP
        SRV_DOMAIN_U,
        SRV_TFTP_U,
        SRV_NTP_U,

        // TCP
        SRV_IRC,
        SRV_X11,
        SRV_Z39_50,
        SRV_AOL,
        SRV_AUTH,
        SRV_BGP,
        SRV_COURIER,
        SRV_CSNET_NS,
        SRV_CTF,
        SRV_DAYTIME,
        SRV_DISCARD,
        SRV_DOMAIN,
        SRV_ECHO,
        SRV_EFS,
        SRV_EXEC,
        SRV_FINGER,
        SRV_FTP,
        SRV_FTP_DATA,
        SRV_GOPHER,
        SRV_HARVEST,
        SRV_HOSTNAMES,
        SRV_HTTP,
        SRV_HTTP_2784,
        SRV_HTTP_443,
        SRV_HTTP_8001,
        SRV_ICMP,
        SRV_IMAP4,
        SRV_ISO_TSAP,
        SRV_KLOGIN,
        SRV_KSHELL,
        SRV_LDAP,
        SRV_LINK,
        SRV_LOGIN,
        SRV_MTP,
        SRV_NAME,
        SRV_NETBIOS_DGM,
        SRV_NETBIOS_NS,
        SRV_NETBIOS_SSN,
        SRV_NETSTAT,
        SRV_NNSP,
        SRV_NNTP,
        SRV_PM_DUMP,
        SRV_POP_2,
        SRV_POP_3,
        SRV_PRINTER,
        SRV_REMOTE_JOB,
        SRV_RJE,
        SRV_SHELL,
        SRV_SMTP,
        SRV_SQL_NET,
        SRV_SSH,
        SRV_SUNRPC,
        SRV_SUPDUP,
        SRV_SYSTAT,
        SRV_TELNET,
        SRV_TIME,
        SRV_UUCP,
        SRV_UUCP_PATH,
        SRV_VMNET,
        SRV_WHOIS,

        // This must be the last
        NUMBER_OF_SERVICES
    };

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
