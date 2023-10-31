package cic.cs.unb.ca.jnetpcap.nslkdd;

import cic.cs.unb.ca.jnetpcap.BasicPacketInfo;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.stream.Collectors;

public class ContentFeatureChecker {

    public static final Logger logger = LoggerFactory.getLogger(ContentFeatureChecker.class);

    public static String getPritableText(Service service, List<BasicPacketInfo> packetInfoList) {
        if( service == Service.SRV_TELNET ) {
            return packetInfoList.stream().filter(content -> content.getPayloadStr() != null
            ).map(content -> content.getPayloadStr()
            ).collect(Collectors.joining());
        } else
            return null;
    }

    public static long getNumFailedLogins(Service service, String backward) {
        if( service == Service.SRV_TELNET ) {
            if( backward == null || backward.length() == 0)
                return 0;

            return StringUtils.countMatches(backward, "Login incorrect");
        }
        return 0;
    }

    public static int isLogin(Service service, String backward) {
        if( service == Service.SRV_TELNET ) {
            if( backward == null || backward.length() == 0 )
                return 0;

            long loginCnt = StringUtils.countMatches(backward, "login: ");
            long passwordCnt = StringUtils.countMatches(backward,"Password: ");
            long welcomeCnt = StringUtils.countMatches(backward, "Welcome ");

//            logger.error("@@@ isLogin loginCnt:"+loginCnt+",passwordCnt:"+passwordCnt+", welcomeCnt:"+welcomeCnt);
            if( loginCnt >= 1 && passwordCnt >= 1 && welcomeCnt >= 1 )
                return 1;
            else
                return 0;
        }
        return 0;
    }

    public static long getNumCompromised(Service service, String backward) {
        if( service == Service.SRV_TELNET ) {
            if( backward == null || backward.length() == 0 )
                return 0;

            return StringUtils.countMatches(backward, "not found") +
                    StringUtils.countMatches(backward, "such file or directory");
        }
        return 0;
    }

    public static long getNumRoot(Service service, String forward, String backward) {
        if( service == Service.SRV_TELNET ) {
            if( forward == null )
                return 0;

            long forwardCnt =  StringUtils.countMatches(forward, "root");
            long backwardCnt =  StringUtils.countMatches(backward, "root");

            return forwardCnt + backwardCnt;
        }
        return 0;
    }
    // ~#
    public static int isRootShell(Service service, String backward, List<BasicPacketInfo> backwardPacketInfo) {
        if( service == Service.SRV_TELNET ) {
            if( backward == null || backwardPacketInfo == null )
                return 0;

            long count = StringUtils.countMatches(backward, "root@");
            long rootSuCount = backwardPacketInfo.stream().filter(
                    content -> content.getPayloadStr() != null && content.getPayloadStr().endsWith("#")
            ).count();
            if( count >= 1 && rootSuCount  >= 1 ) {
                return 1;
            }
        }
        return 0;
    }
    public static int isSuAttempted(Service service, String forward) {
        if( service == Service.SRV_TELNET ) {
            if( forward == null )
                return 0;

            long count = StringUtils.countMatches(forward, "su ");
            if( count >= 1 )
                return 1;
        }
        return 0;
    }

    // 'vi', 'cp', 'chmod', 'rm' 및 'cat
    public static long getNumFileCreation(Service service, String forward) {
        if( service == Service.SRV_TELNET ) {
            if( forward == null )
                return 0;

            return StringUtils.countMatches(forward, "vi ") +
                    StringUtils.countMatches(forward, "cp ") +
                    StringUtils.countMatches(forward, "chmod ") +
                    StringUtils.countMatches(forward, "rm ") +
                    StringUtils.countMatches(forward, "cat ");
        }
        return 0;
    }

    public static long getNumShells(Service service, String forward, String backward) {
        if( service == Service.SRV_TELNET ) {
            if( forward == null )
                return 0;

            return StringUtils.countMatches(forward,"/bin/sh") +
                    StringUtils.countMatches(forward,"/bin/bash") +
                    StringUtils.countMatches(backward,"/bin/sh") +
                    StringUtils.countMatches(backward,"/bin/bash");
        }
        return 0;
    }

    // '/bin/sh', '/bin/bash'
    public static int isHostLogin(Service service, String forward) {
        if( service == Service.SRV_TELNET ) {
            long count = StringUtils.countMatches(forward, "login: root");
            if( count >= 1 )
                return 1;
        }
        return 0;
    }

}
