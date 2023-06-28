package cic.cs.unb.ca.jnetpcap.nslkdd;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

import static cic.cs.unb.ca.jnetpcap.nslkdd.NSLKDDConst.icmp_field_type_t.*;
import static cic.cs.unb.ca.jnetpcap.nslkdd.NSLKDDConst.service_t.*;

public class NSLKDDUtility {

    public static final Logger logger = LoggerFactory.getLogger(NSLKDDUtility.class);
    /* CHECK:: TCP SERVICE */
    public static NSLKDDConst.service_t get_service_tcp(int srcPort, int dstPort)
    {
        // Identify FTP data in active FTP can be identified by source port
        // TODO: passive FTP (only through FTP control payload inspection?)
        switch (srcPort) {
            case 20:
                return NSLKDDConst.service_t.SRV_FTP_DATA;
            // case 22:
            // 	return SRV_SSH;
        }

        // Service ports assigned according to IANA Service Name and Transport Protocol Port Number Registry
        // https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xml
        switch (dstPort)
        {
            case 194: // Internet Relay Chat Protocol
            case 529: // IRC-SERV
            case 2218: // Bounzza IRC Proxy
            case 6665: // IRCU (6665-6669)
            case 6666:
            case 6668:
            case 6669:
            case 6697: // Internet Relay Chat via TLS/SSL
                return SRV_IRC;

            case 6000: // X Window System (6000-6063)
            case 6001:
            case 6002:
            case 6003:
            case 6004:
            case 6005:
            case 6006:
            case 6007:
            case 6008:
            case 6009:
            case 6010:
            case 6011:
            case 6012:
            case 6013:
            case 6014:
            case 6015:
            case 6016:
            case 6017:
            case 6018:
            case 6019:
            case 6020:
            case 6021:
            case 6022:
            case 6023:
            case 6024:
            case 6025:
            case 6026:
            case 6027:
            case 6028:
            case 6029:
            case 6030:
            case 6031:
            case 6032:
            case 6033:
            case 6034:
            case 6035:
            case 6036:
            case 6037:
            case 6038:
            case 6039:
            case 6040:
            case 6041:
            case 6042:
            case 6043:
            case 6044:
            case 6045:
            case 6046:
            case 6047:
            case 6048:
            case 6049:
            case 6050:
            case 6051:
            case 6052:
            case 6053:
            case 6054:
            case 6055:
            case 6056:
            case 6057:
            case 6058:
            case 6059:
            case 6060:
            case 6061:
            case 6062:
            case 6063:
                return SRV_X11;

            case 210: // ANSI Z39.50
                return SRV_Z39_50;

            case 5190: // America-Online
            case 5191: // AmericaOnline1
            case 5192: // AmericaOnline2
            case 5193: // AmericaOnline3
            case 531: // AOL Instant Messenger
                return SRV_AOL;

            case 113: // Authentication Service
            case 31: // MSG Authentication
            case 56: // XNS Authentication
            case 222: // Berkeley rshd with SPX auth
            case 353: // NDSAUTH
            case 370: // codaauth2
            case 1615: // NetBill Authorization Server
            case 2139: // IAS-AUTH
            case 2147: // Live Vault Authentication
            case 2334: // ACE Client Auth
            case 2392: // Tactical Auth
            case 2478: // SecurSight Authentication Server (SSL)
            case 2821: // VERITAS Authentication Service
            case 3113: // CS-Authenticate Svr Port
            case 3207: // Veritas Authentication Port
            case 3710: // PortGate Authentication
            case 3799: // RADIUS Dynamic Authorization
            case 3810: // WLAN AS server
            case 3833: // AIPN LS Authentication
            case 3871: // Avocent DS Authorization
            case 4032: // VERITAS Authorization Service
            case 4129: // NuFW authentication protocol
            case 4373: // Remote Authenticated Command Service
            case 5067: // Authentx Service
            case 5635: // SFM Authentication Subsystem
            case 6268: // Grid Authentication
            case 6269: // Grid Authentication Alt
            case 7004: // AFS/Kerberos authentication service
            case 7847: // A product key authentication protocol made by CSO
            case 9002: // DynamID authentication
            case 19194: // UserAuthority SecureAgent
            case 27999: // TW Authentication/Key Distribution and
                return SRV_AUTH;

            case 179: // Border Gateway Protocol
                return SRV_BGP;

            case 530: // rpc
            case 165: // Xerox (xns-courier)
                return SRV_COURIER;

            case 105: // Mailbox Name Nameserver
                return SRV_CSNET_NS;

            case 84: // Common Trace Facility
                return SRV_CTF;

            case 13: // Daytime
                return SRV_DAYTIME;

            case 9: // Discard
                return SRV_DISCARD;

            case 53: // Domain Name Server
                return SRV_DOMAIN;

            case 7: //
                return SRV_ECHO;

            case 520: // extended file name server
                return SRV_EFS;

            case 512: // remote process execution; authentication performed using passwords and UNIX login names
                return SRV_EXEC;

            case 79: // Finger
                return SRV_FINGER;

            case 21: // File Transfer Protocol [Control]
                return SRV_FTP;

            case 20: // File Transfer [Default Data] (TODO)
                return SRV_FTP_DATA;

            case 70: // Gopher
                return SRV_GOPHER;

            // TODO: service harvest port number
            //case: //
            //	return SRV_HARVEST;
            //	break;

            case 101: // NIC Host Name Server
                return SRV_HOSTNAMES;

            case 80: // World Wide Web HTTP
            case 8008: // HTTP Alternate
            case 8080: // HTTP Alternate
                return SRV_HTTP;

            case 2784: // world wide web - development (www-dev)
                return SRV_HTTP_2784;

            case 443: // http protocol over TLS/SSL
                return SRV_HTTP_443;

            case 8001: // VCOM Tunnel(iana) / Commonly used for Internet radio streams such as SHOUTcast (wiki)
                return SRV_HTTP_8001;

            case 5813: // ICMPD
                return SRV_ICMP;

            case 143: // imap4 protocol over TLS/SSL (imaps)
            case 993: // imap4 protocol over TLS/SSL (imaps)
                return SRV_IMAP4;

            case 102: // ISO-TSAP Class 0
            case 309: // ISO Transport Class 2 Non-Control over TCP
                return SRV_ISO_TSAP;

            case 543: // klogin
                return SRV_KLOGIN;

            case 544: // krcmd
                return SRV_KSHELL;

            case 389: // Lightweight Directory Access Protocol
            case 636: // ldap protocol over TLS/SSL (was sldap) (ldaps)
                return SRV_LDAP;

            case 245: // LINK
                return SRV_LINK;

            case 513: // "remote login a la telnet; automatic authentication performed based on priviledged port numbers and distributed data bases which identify ""authentication domains"""
                return SRV_LOGIN;

            case 1911: // Starlight Networks Multimedia Transport Protocol
                return SRV_MTP;

            case 42: // Host Name Server
                return SRV_NAME;

            case 138: // NETBIOS Datagram Service
                return SRV_NETBIOS_DGM;

            case 137: // NETBIOS Name Service
                return SRV_NETBIOS_NS;

            case 139: // NETBIOS Session Service
                return SRV_NETBIOS_SSN;

            case 15: // Unassigned [was netstat]
                return SRV_NETSTAT;

            case 433: // NNSP
                return SRV_NNSP;

            case 119: // Network News Transfer Protocol
            case 563: // nntp protocol over TLS/SSL (was snntp)
                return SRV_NNTP;

            // TODO: service pm_dump port number
            //case: //
            //	return SRV_PM_DUMP;
            //	break;

            case 109: // Post Office Protocol Version 2
                return SRV_POP_2;

            case 110: // Post Office Protocol Version 3
                return SRV_POP_3;

            case 515: // spooler
                return SRV_PRINTER;

            case 71: // Remote Job Service (netrjs-1)
            case 72: // Remote Job Service (netrjs-2)
            case 73: // Remote Job Service (netrjs-3)
            case 74: // Remote Job Service (netrjs-4)
                return SRV_REMOTE_JOB;

            case 5: // Remote Job Entry
            case 77: // any private RJE service
                return SRV_RJE;

            case 514: // "cmd like exec
                return SRV_SHELL;

            case 25: // Simple Mail Transfer
                return SRV_SMTP;

            case 66: // Oracle SQL*NET
            case 150: // SQL-NET
                return SRV_SQL_NET;

            case 22: // The Secure Shell (SSH) Protocol
                return SRV_SSH;

            case 111: // SUN Remote Procedure Call
                return SRV_SUNRPC;

            case 95: // SUPDUP
                return SRV_SUPDUP;

            case 11: // Active Users
                return SRV_SYSTAT;

            case 23: // Telnet
                return SRV_TELNET;

            case 37: // Time
                return SRV_TIME;

            case 540: // uucpd
            case 4031: // UUCP over SSL
                return SRV_UUCP;

            case 117: // UUCP Path Service
                return SRV_UUCP_PATH;

            case 175: // VMNET
                return SRV_VMNET;

            case 43: // Who Is
            case 4321: // Remote Who Is (rwhois)
                return SRV_WHOIS;

            default:
                // Private ports defined by IANA in RFC 6335 section 6:
                // Dynamic Ports, also known as the Private or Ephemeral Ports,
                // from 49152 - 65535 (never assigned)
                if ( dstPort >= 49152)
                    return SRV_PRIVATE; // or other?
                else {
                    logger.error("srcPort:{} dstPort:{}", srcPort, dstPort);
                    return SRV_OTHER;
                }
        }
    }

    /* CHECK:: UDP SERVICE */
    public static NSLKDDConst.service_t get_service_udp(int srcPort, int dstPort)
    {
        switch (dstPort)
        {
            case 53:	// DNS
                return SRV_DOMAIN_U;

            case 69:	// TFTP
                return SRV_TFTP_U;

            case 123:	// NTP
                return SRV_NTP_U;

            default:
                // Defined by IANA in RFC 6335 section 6:
                // the Dynamic Ports, also known as the Private or Ephemeral Ports,
                // from 49152 - 65535 (never assigned)
                if ( dstPort >= 49152)
                    return SRV_PRIVATE;
                else
                    return SRV_OTHER;
        }
    }

    /* CHECK:: ICMP SERVICE */
    public static NSLKDDConst.service_t get_service_icmp(NSLKDDConst.icmp_field_type_t icmp_type, int icmp_code)
    {
        switch (icmp_type)
        {
            case ECHOREPLY:
                return SRV_ECR_I;	// Echo Reply (0)

            case DEST_UNREACH:
                if (icmp_code == 0)			// Destination network unreachable
                    return SRV_URP_I;
                else if (icmp_code == 1)	// Destination host unreachable
                    return SRV_URH_I;
                else
                    return SRV_OTH_I;		// Other ICMP messages;

            case REDIRECT:
                return SRV_RED_I;	// Redirect message (5)

            case ECHO:
                return SRV_ECO_I;	// Echo Request (8)

            case TIME_EXCEEDED:		// Time Exceeded (11)
                return SRV_TIM_I;

            default:
                return SRV_OTH_I;	// Other ICMP messages;
        }
    }

    /*
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
     */

    public static NSLKDDConst.icmp_field_type_t getIcmpType(int icmpType) {

        switch(icmpType) {
            case 0:
                return ECHOREPLY;
            case 3:
                return DEST_UNREACH;
            case 4:
                return SOURCE_QUENCH;
            case 5:
                return REDIRECT;
            case 8:
                return ECHO;
            case 11:
                return TIME_EXCEEDED;
            case 12:
                return PARAMETERPROB;
            case 13:
                return TIMESTAMP;
            case 14:
                return TIMESTAMPREPLY;
            case 15:
                return INFO_REQUEST;
            case 16:
                return INFO_REPLY;
            case 17:
                return ADDRESS;
            case 18:
                return ADDRESSREPLY;
            default:
                return ECHOREPLY;
        }
    }
    public static String preditRequest(String url, String jsonData) {

        CloseableHttpClient client = null;
        BufferedReader in = null;
        StringBuffer result = new StringBuffer();

        try {
            client = HttpClients.createDefault();
            HttpPost httpPost = new HttpPost(url);

            // 헤더 설정이 필요한 경우
            //httpPost.setHeader("header_key", "header_value");

            // JSON 데이터를 추가.
            httpPost.setEntity(new StringEntity(jsonData, ContentType.APPLICATION_JSON));

            // Key / Value 속성으로 할 경우
            // List<NameValuePair> params = new ArrayList<NameValuePair>();
            // params.add(new BasicNameValuePair("key", "value"));
            // httpPost.setEntity(new UrlEncodedFormEntity(params));

            // 실행
            CloseableHttpResponse httpresponse = client.execute(httpPost);

            // 결과 수신
            InputStream inputStream = (InputStream)httpresponse.getEntity().getContent();

            String inputLine = null;
            in = new BufferedReader(new InputStreamReader(inputStream, "utf-8"));

            while((inputLine = in.readLine()) != null) {
                result.append(inputLine);
            }

            JSONParser parser = new JSONParser();
            JSONObject json = (JSONObject) parser.parse(result.toString());
            JSONObject resultJson = (JSONObject)json.get("result");
            String pred = (String)resultJson.get("pred");

            return pred;
        }catch(IOException ioe) {
            logger.error("", ioe);
        } catch (ParseException e) {
            logger.error("", e);
        } finally {
            if(in != null) {
                try {
                    in.close();
                } catch(IOException ioe) { throw ioe; }
            }
        }
    }
}
