package cic.cs.unb.ca.jnetpcap.nslkdd;

import cic.cs.unb.ca.jnetpcap.BasicPacketInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

public class ContentFeatureChecker {

    public static final Logger logger = LoggerFactory.getLogger(ContentFeatureChecker.class);

    public static long getNumFailedLogins(Service service, List<BasicPacketInfo> backward) {
        if( service == Service.SRV_TELNET ) {
            if( backward == null )
                return 0;
            return backward.stream().filter(content -> content.getPayloadStr() != null && content.getPayloadStr().contains("Login incorrect")).count();
        }
        return 0;
    }

    public static int isLogin(Service service, List<BasicPacketInfo> backward) {
        if( service == Service.SRV_TELNET ) {
            if( backward == null )
                return 0;

            long loginCnt = backward.stream().filter(content -> content.getPayloadStr() != null && content.getPayloadStr().contains("login: ")).count();
            long passwordCnt = backward.stream().filter(content -> content.getPayloadStr() != null && content.getPayloadStr().contains("Password: ")).count();
            long welcomeCnt = backward.stream().filter(content -> content.getPayloadStr() != null && content.getPayloadStr().contains("Welcome ")).count();

            logger.error("@@@ isLogin loginCnt:"+loginCnt+",passwordCnt:"+passwordCnt+", welcomeCnt:"+welcomeCnt);
            if( loginCnt >= 1 && passwordCnt >= 1 && welcomeCnt >= 1 )
                return 1;
            else
                return 0;
        }
        return 0;
    }

    public static long getNumCompromised(Service service, List<BasicPacketInfo> backward) {
        if( service == Service.SRV_TELNET ) {
            if( backward == null )
                return 0;

            return backward.stream().filter(content -> content.getPayloadStr() != null &&
                    (   content.getPayloadStr().contains("not found") ||
                        content.getPayloadStr().contains("such file or directory"))
            ).count();
        }
        return 0;
    }

    public static long getNumRoot(Service service, List<BasicPacketInfo> forward, List<BasicPacketInfo> backward) {
        if( service == Service.SRV_TELNET ) {
            if( forward == null )
                return 0;

            long forwardCnt =  forward.stream().filter(content ->  content.getPayloadStr() != null &&
                    content.getPayloadStr().contains("root")).count();

            long backwardCnt =  backward.stream().filter(content ->  content.getPayloadStr() != null &&
                    content.getPayloadStr().contains("root")).count();

            return forwardCnt + backwardCnt;
        }
        return 0;
    }
    // ~#
    public static int isRootShell(Service service, List<BasicPacketInfo> backward) {
        if( service == Service.SRV_TELNET ) {
            if( backward == null )
                return 0;

            long count = backward.stream().filter(content -> content.getPayloadStr() != null &&
                    content.getPayloadStr().startsWith("root@") && content.getPayloadStr().endsWith("#")
            ).count();
            if( count >= 1 ) {
                return 1;
            }
        }
        return 0;
    }
    public static int isSuAttempted(Service service, List<BasicPacketInfo> forward) {
        if( service == Service.SRV_TELNET ) {
            if( forward == null )
                return 0;

            long count = forward.stream().filter(content -> content.getPayloadStr() != null &&
                            (
                            content.getPayloadStr().contains("su ") ||
                            content.getPayloadStr().contains("su -") ||
                            content.getPayloadStr().contains("su ")
                            )
                    ).count();
            if( count >= 1 )
                return 1;
        }
        return 0;
    }

    // 'vi', 'cp', 'chmod', 'rm' 및 'cat
    public static long getNumFileCreation(Service service, List<BasicPacketInfo> forward) {
        if( service == Service.SRV_TELNET ) {
            if( forward == null )
                return 0;

//            String forwardText = forward.stream().filter(content -> content.getPayloadStr() != null
//            ).map( content -> content.getPayloadStr()
//            ).collect(Collectors.joining());
            StringBuffer sb = new StringBuffer();
            for( int i=0; i<forward.size();i++ ) {
                sb.append(forward.get(i).getPayloadStr());
                logger.error("@@@ getNumFileCreation index["+i+"]: " + forward.get(i).getPayloadStr());
            }

            logger.error("@@@ getNumFileCreation forwardText:" + sb.toString());

            return forward.stream().filter(content ->  content.getPayloadStr() != null &&
                (
                    content.getPayloadStr().contains("vi ") ||
                    content.getPayloadStr().contains("cp ") ||
                    content.getPayloadStr().contains("chmod ") ||
                    content.getPayloadStr().contains("rm ") ||
                    content.getPayloadStr().contains("cat ")
                )
            ).count();
        }
        return 0;
    }

    public static long getNumShells(Service service, List<BasicPacketInfo> forward, List<BasicPacketInfo> backward) {
        if( service == Service.SRV_TELNET ) {
            if( forward == null )
                return 0;

            return forward.stream().filter(content -> content.getPayloadStr() != null &&
                            (
                                    content.getPayloadStr().contains("‘/bin/sh") ||
                                    content.getPayloadStr().contains("‘/bin/bash")
                            )
            ).count() +
            backward.stream().filter(content -> content.getPayloadStr() != null &&
                    (
                            content.getPayloadStr().contains("‘/bin/sh") ||
                                    content.getPayloadStr().contains("‘/bin/bash")
                    )
            ).count()
                    ;
        }
        return 0;
    }

    // '/bin/sh', '/bin/bash'
    public static int isHostLogin(Service service, List<BasicPacketInfo> forward) {
        if( service == Service.SRV_TELNET ) {
            long count = forward.stream().filter(content -> content.getPayloadStr() != null &&
                    content.getPayloadStr().contains("login: root")
            ).count();

            if( count >= 1 )
                return 1;
        }
        return 0;
    }

}
