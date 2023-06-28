package cic.cs.unb.ca.jnetpcap.nslkdd;


import org.apache.commons.lang3.math.NumberUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

public enum Service {

    /**
     * Services
     * ! order & number of services must be the same in string mapping
     * see Conversation::SERVICE_NAMES[] in Conversation.cpp
     */

    // General
    SRV_OTHER("SRV_OTHER", 42),
    SRV_PRIVATE("SRV_PRIVATE", 47),


    // ICMP
    SRV_ECR_I("SRV_ECR_I", 12),
    SRV_URP_I("SRV_URP_I", 63),
    SRV_URH_I("SRV_URH_I", 62),
    SRV_RED_I("SRV_RED_I", 48),
    SRV_ECO_I("SRV_ECO_I", 11),
    SRV_TIM_I("SRV_TIM_I", 60),
    SRV_OTH_I("SRV_OTH_I", 42),


    // UDP
    SRV_DOMAIN_U("SRV_DOMAIN_U", 9),
    SRV_TFTP_U("SRV_TFTP_U", 59),
    SRV_NTP_U("SRV_NTP_U", 41),

    // TCP
    SRV_IRC("SRV_IRC", 26),
    SRV_X11("SRV_X11", 68),
    SRV_Z39_50("SRV_Z39_50", 69),
    SRV_AOL("SRV_AOL", 0),
    SRV_AUTH("SRV_AUTH", 1),
    SRV_BGP("SRV_BGP", 2),
    SRV_COURIER("SRV_COURIER", 3),
    SRV_CSNET_NS("SRV_CSNET_NS", 4),
    SRV_CTF("SRV_CTF", 5),
    SRV_DAYTIME("SRV_DAYTIME", 6),
    SRV_DISCARD("SRV_DISCARD", 7),
    SRV_DOMAIN("SRV_DOMAIN", 8),
    SRV_ECHO("SRV_ECHO", 10),
    SRV_EFS("SRV_EFS", 13),
    SRV_EXEC("SRV_EXEC", 14),
    SRV_FINGER("SRV_FINGER", 15),
    SRV_FTP("SRV_FTP", 16),
    SRV_FTP_DATA("SRV_FTP_DATA", 17),
    SRV_GOPHER("SRV_GOPHER", 18),
    SRV_HARVEST("SRV_HARVEST", 19),
    SRV_HOSTNAMES("SRV_HOSTNAMES", 20),
    SRV_HTTP("SRV_HTTP", 21),
    SRV_HTTP_2784("SRV_HTTP_2784", 22),
    SRV_HTTP_443("SRV_HTTP_443", 23),
    SRV_HTTP_8001("SRV_HTTP_8001", 24),
    SRV_ICMP("SRV_ICMP", 42),
    SRV_IMAP4("SRV_IMAP4", 25),
    SRV_ISO_TSAP("SRV_ISO_TSAP", 27),
    SRV_KLOGIN("SRV_KLOGIN", 28),
    SRV_KSHELL("SRV_KSHELL", 29),
    SRV_LDAP("SRV_LDAP", 30),
    SRV_LINK("SRV_LINK", 31),
    SRV_LOGIN("SRV_LOGIN", 32),
    SRV_MTP("SRV_MTP", 33),
    SRV_NAME("SRV_NAME", 34),
    SRV_NETBIOS_DGM("SRV_NETBIOS_DGM", 35),
    SRV_NETBIOS_NS("SRV_NETBIOS_NS", 36),
    SRV_NETBIOS_SSN("SRV_NETBIOS_SSN", 37),
    SRV_NETSTAT("SRV_NETSTAT", 38),
    SRV_NNSP("SRV_NNSP", 39),
    SRV_NNTP("SRV_NNTP", 40),
    SRV_PM_DUMP("SRV_PM_DUMP", 43),
    SRV_POP_2("SRV_POP_2", 44),
    SRV_POP_3("SRV_POP_3", 45),
    SRV_PRINTER("SRV_PRINTER", 46),
    SRV_REMOTE_JOB("SRV_REMOTE_JOB", 49),
    SRV_RJE("SRV_RJE", 50),
    SRV_SHELL("SRV_SHELL", 51),
    SRV_SMTP("SRV_SMTP", 52),
    SRV_SQL_NET("SRV_SQL_NET", 53),
    SRV_SSH("SRV_SSH", 54),
    SRV_SUNRPC("SRV_SUNRPC", 55),
    SRV_SUPDUP("SRV_SUPDUP", 56),
    SRV_SYSTAT("SRV_SYSTAT", 57),
    SRV_TELNET("SRV_TELNET", 58),
    SRV_TIME("SRV_TIME", 61),
    SRV_UUCP("SRV_UUCP", 64),
    SRV_UUCP_PATH("SRV_UUCP_PATH", 65),
    SRV_VMNET("SRV_VMNET", 66),
    SRV_WHOIS("SRV_WHOIS", 67),
    ;


	protected static final Logger logger = LoggerFactory.getLogger(Service.class);
	private static String HEADER;
	private String name;
	private int code;

    Service(String name, int code) {
        this.name = name;
        this.code = code;
    }

	public String getName() {
		return name;
	}

    public int getCode() {
        return code;
    }

	public static Service getByName(String name) {
		for(Service feature: Service.values()) {
			if(feature.getName().equals(name)) {
				return feature;
			}
		}
		return null;
	}

	@Override
	public String toString() {
		return name;
	}
	
}
