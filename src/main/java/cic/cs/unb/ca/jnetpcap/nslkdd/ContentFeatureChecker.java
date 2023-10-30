package cic.cs.unb.ca.jnetpcap.nslkdd;

import cic.cs.unb.ca.jnetpcap.BasicPacketInfo;

import java.util.List;

public class ContentFeatureChecker {

    public static long getNumFailedLogins(Service service, List<BasicPacketInfo> forward) {
        if( service == Service.SRV_TELNET ) {
            return forward.stream().filter(content -> content.getPayloadStr().contains("Login incorrect")).count();
        }
        return 0;
    }

    public static int isLogin(Service service, List<BasicPacketInfo> forward) {
        if( service == Service.SRV_TELNET ) {
            long loginCnt = forward.stream().filter(content -> content.getPayloadStr().contains("login: ")).count();
            long passwordCnt = forward.stream().filter(content -> content.getPayloadStr().contains("Password: ")).count();
            long welcomeCnt = forward.stream().filter(content -> content.getPayloadStr().contains("Welcome: ")).count();

            if( loginCnt >= 1 && passwordCnt >= 1 && welcomeCnt >= 1 )
                return 1;
            else
                return 0;
        }
        return 0;
    }

    public static long getNumCompromised(Service service, List<BasicPacketInfo> forward) {
        if( service == Service.SRV_TELNET ) {
            return forward.stream().filter(content -> content.getPayloadStr().contains("not found") || content.getPayloadStr().contains("such file or directory") ).count();
        }
        return 0;
    }

    public static long getNumRoot(Service service, List<BasicPacketInfo> backword) {
        if( service == Service.SRV_TELNET ) {
            return backword.stream().filter(content -> content.getPayloadStr().contains("root") ).count();
        }
        return 0;
    }
    // ~#
    public static int isRootShell(Service service, List<BasicPacketInfo> forward) {
        if( service == Service.SRV_TELNET ) {
            long count = forward.stream().filter(content -> content.getPayloadStr().endsWith("~#") ).count();
            if( count >= 1 )
                return 1;
        }
        return 0;
    }
    public static int isSuAttempted(Service service, List<BasicPacketInfo> backword) {
        if( service == Service.SRV_TELNET ) {
            long count = backword.stream().filter(content -> content.getPayloadStr().contains("su ") ||
                            content.getPayloadStr().contains("su -") ||
                            content.getPayloadStr().contains("su ")
                    ).count();
            if( count > 1 )
                return 1;
        }
        return 0;
    }

    // 'vi', 'cp', 'chmod', 'rm' 및 'cat
    public static long getNumFileCreation(Service service, List<BasicPacketInfo> forward) {
        if( service == Service.SRV_TELNET ) {
            return forward.stream().filter(content -> content.getPayloadStr().contains("vi ") ||
                    content.getPayloadStr().contains("cp ") ||
                    content.getPayloadStr().contains("chmod ") ||
                    content.getPayloadStr().contains("rm ") ||
                    content.getPayloadStr().contains("cat ")
            ).count();
        }
        return 0;
    }

    public static long getNumShells(Service service, List<BasicPacketInfo> forward) {
        if( service == Service.SRV_TELNET ) {
            return forward.stream().filter(content -> content.getPayloadStr().contains("‘/bin/sh") ||
                    content.getPayloadStr().contains("‘/bin/bash")
            ).count();
        }
        return 0;
    }

    // '/bin/sh', '/bin/bash'
    public static int isHostLogin(Service service, List<BasicPacketInfo> forward) {
        if( service == Service.SRV_TELNET ) {
            long count = forward.stream().filter(content -> content.getPayloadStr().contains("login: root")
            ).count();

            if( count >= 1 )
                return 1;
        }
        return 0;
    }

}
