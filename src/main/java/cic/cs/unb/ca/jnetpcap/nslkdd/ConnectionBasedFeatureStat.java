package cic.cs.unb.ca.jnetpcap.nslkdd;

import cic.cs.unb.ca.jnetpcap.FlowGenerator;
import net.jodah.expiringmap.ExpirationPolicy;
import net.jodah.expiringmap.ExpiringMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

public class ConnectionBasedFeatureStat implements Runnable{
    public static final Logger logger = LoggerFactory.getLogger(ConnectionBasedFeatureStat.class);
    private Map<String, Integer> srvCountOrgMap = null;
    private Map<String, Integer> srvCountMap = null;
    private int checkConnectionCount = 10000;
    private long monitorPeriod = 1 * 1 * 1000L;

    public ConnectionBasedFeatureStat(int checkConnectionCount) {
        this.checkConnectionCount = checkConnectionCount;

        srvCountOrgMap = ExpiringMap.builder()
                .maxSize(this.checkConnectionCount)
                .expirationPolicy(ExpirationPolicy.CREATED)
                .expiration(1, TimeUnit.DAYS)
                .build();
    }
    @Override
    public void run() {
        try {
            while( !Thread.interrupted() ) {
                logger.error("ConnectionBasedFeatureStat-srvCountMap count:" + srvCountOrgMap.size());
                Thread.sleep(this.monitorPeriod);

                try {
                    synchronized (srvCountOrgMap) {
                        srvCountMap = new HashMap<>();
                        srvCountMap.putAll(srvCountOrgMap);
                    }
                } catch (Exception ex) {
                    logger.error("",ex);
                }
            }
        } catch (InterruptedException e) {
            logger.error("",e);
            throw new RuntimeException(e);
        }
    }

    private String makeKey(String srdIp, int srcPort, String dstIp, int dstPort, int protocol, Flag flag) {
        StringBuffer sb = new StringBuffer();

        sb.append("P").append("=").append(protocol);
        sb.append("SI").append("=").append(srdIp);
        sb.append("SP").append("=").append(srcPort);
        sb.append("DI").append("=").append(dstIp);
        sb.append("DP").append("=").append(dstPort);
        sb.append("F").append("=").append(flag);

        return sb.toString();
    }

    public void addConnection(String srcIp, int srcPort, String dstIp, int dstPort, int protocol, Flag flag ) {
        logger.error("addConnection  getDstHostCount {}_{}", dstIp, protocol);

        String key = makeKey(srcIp, srcPort, dstIp, dstPort, protocol, flag);
        synchronized (srvCountOrgMap) {
            if( srvCountOrgMap.containsKey(key) ) {
                int tmpCount = srvCountOrgMap.get(key);
                srvCountOrgMap.put(key, tmpCount+1);
            } else {
                srvCountOrgMap.put(key, 1);
            }
        }
    }
    public int getDstHostCount(String dstIp, int dstPort, int protocol) {
        int count = srvCountMap.keySet().stream().filter(key -> key.startsWith("P="+protocol) && key.indexOf("DI="+dstIp) > -1).mapToInt( key -> srvCountMap.get(key)).sum();
        logger.error("srvCountMap{} getDstHostCount {}_{}: {}", srvCountMap.size(), dstIp, protocol, count);
        return count;
    }
    public int getDstHostSrvCount(String dstIp, int dstPort, int protocol) {
        return srvCountMap.keySet().stream().filter(key -> key.startsWith("P="+protocol) &&  key.indexOf("DP="+dstPort) > -1).mapToInt( key -> srvCountMap.get(key)).sum();
    }
    public int getDstHostSameSrvCount(String dstIp, int dstPort, int protocol) {
        return srvCountMap.keySet().stream().filter(key -> key.startsWith("P="+protocol) && key.indexOf("DI="+dstIp) > -1 && key.indexOf("DP="+dstPort) >  -1).mapToInt( key -> srvCountMap.get(key)).sum();
    }
    public double getDstHostSameSrvRate(String dstIp, int dstPort, int protocol) {
        double dstHostCount = (double)this.getDstHostCount(dstIp, dstPort, protocol);
        double dstHostSrvCount = (double)this.getDstHostSameSrvCount(dstIp, dstPort, protocol);

        logger.info("dstHostCount:{}, dstHostSrvCount:{} rate:{}", dstHostCount, dstHostSrvCount, dstHostCount == 0 ? 0 : dstHostCount < dstHostSrvCount ? 1 : (dstHostSrvCount / dstHostCount));
        return dstHostCount == 0 ? 0 : dstHostCount < dstHostSrvCount ? 1 : (dstHostSrvCount / dstHostCount);
    }
    public int getDstHostDiffSrvCount(String dstIp, int dstPort, int protocol) {
        return srvCountMap.keySet().stream().filter(key -> key.startsWith("P="+protocol) && key.indexOf("DI="+dstIp) > -1 && key.indexOf("DP="+dstPort)==-1).mapToInt( key -> srvCountMap.get(key)).sum();
    }
    public double getDstHostDiffSrvRate(String dstIp, int dstPort, int protocol) {
        double dstHostCount = (double)this.getDstHostCount(dstIp, dstPort, protocol);
        double dstHostDiffSrvCount = (double)this.getDstHostDiffSrvCount(dstIp, dstPort, protocol);

        return dstHostCount == 0 ? 0 : dstHostCount < dstHostDiffSrvCount ? 1 : (dstHostDiffSrvCount / dstHostCount);
    }
    //36 Dst Host Same Src Port Rate
    public int getDstHostSameSrcPortCount(String dstIp, int dstPort, String srcIp, int srcPort, int protocol) {
        return srvCountMap.keySet().stream().filter(key -> key.startsWith("P="+protocol) &&  key.indexOf("DP="+dstPort) > -1 && key.indexOf("SP="+srcPort) > -1 ).mapToInt( key -> srvCountMap.get(key)).sum();
    }
    public double getDstHostSameSrcPortRate(String dstIp, int dstPort, String srcIp, int srcPort,int protocol) {
        double dstHostSameSrvCount = (double)this.getDstHostSameSrvCount(dstIp, dstPort, protocol);
        double dstHostSameSrcPortCount = (double)this.getDstHostSameSrcPortCount(dstIp, dstPort, srcIp, srcPort, protocol);

        return dstHostSameSrvCount == 0 ? 0 : dstHostSameSrvCount < dstHostSameSrcPortCount ? 1 : (dstHostSameSrcPortCount / dstHostSameSrvCount);
    }
    //37	Dst Host Srv Diff Host Rate
    public int getDstHostSrvDiffHostCount(String dstIp, int dstPort, String srcIp, int srcPort, int protocol) {
        return srvCountMap.keySet().stream().filter(key -> key.startsWith("P="+protocol) &&  key.indexOf("DP="+dstPort) > -1 && key.indexOf("DI="+dstIp)==-1).mapToInt( key -> srvCountMap.get(key)).sum();
    }
    public double getDstHostSrvDiffHostRate(String dstIp, int dstPort, String srcIp, int srcPort,int protocol) {
        double dstHostSameSrvCount = (double)this.getDstHostSameSrvCount(dstIp, dstPort, protocol);
        double dstHostSrvDiffHostCount = (double)this.getDstHostSrvDiffHostCount(dstIp, dstPort, srcIp, srcPort, protocol);

        return dstHostSameSrvCount == 0 ? 0 : dstHostSameSrvCount < dstHostSrvDiffHostCount ? 1 : (dstHostSrvDiffHostCount / dstHostSameSrvCount);
    }
    //38	Dst Host Serror Rate
    public int getDstHostSerrorCount(String dstIp, int protocol, Flag flag)  {
        return srvCountMap.keySet().stream().filter(key -> key.startsWith("P="+protocol) && key.indexOf("DI="+dstIp) > -1 && (
                        key.indexOf("F="+Flag.S0) > -1
                        || key.indexOf("F="+Flag.S1) > -1
                        || key.indexOf("F="+Flag.S2) > -1
                        || key.indexOf("F="+Flag.S3) > -1
        )).mapToInt( key -> srvCountMap.get(key)).sum();
    }
    public double getDstHostSerrorRate(String dstIp, int dstPort, String srcIp, int srcPort,int protocol, Flag flag) {
        double dstHostCount = (double)this.getDstHostCount(dstIp, dstPort, protocol);
        double dstHostSerrorCount = (double)this.getDstHostSerrorCount(dstIp, protocol, flag);

        return dstHostCount == 0 ? 0 : dstHostCount < dstHostSerrorCount ? 1 : (dstHostSerrorCount / dstHostCount);
    }
    //39	Dst Host Srv Serror Rate
    public int getDstHostSrvSerrorCount(int dstPort, int protocol, Flag flag)  {
        return srvCountMap.keySet().stream().filter(key -> key.startsWith("P="+protocol) &&  key.indexOf("DP="+dstPort) > -1 && (
                key.indexOf("F="+Flag.S0) > -1
                        || key.indexOf("F="+Flag.S1) > -1
                        || key.indexOf("F="+Flag.S2) > -1
                        || key.indexOf("F="+Flag.S3) > -1
        )).mapToInt( key -> srvCountMap.get(key)).sum();
    }
    public double getDstHostSrvSerrorRate(String dstIp, int dstPort, String srcIp, int srcPort,int protocol, Flag flag) {
        double dstHostSameSrvCount = (double)this.getDstHostSameSrvCount(dstIp, dstPort, protocol);
        double dstHostSrvSerrorCount = (double)this.getDstHostSrvSerrorCount(dstPort, protocol, flag);

        return dstHostSameSrvCount == 0 ? 0 : dstHostSameSrvCount < dstHostSrvSerrorCount ? 1 : (dstHostSrvSerrorCount / dstHostSameSrvCount);
    }
    //40	Dst Host Rerror Rate
    public int getDstHostRerrorCount(String dstIp, int protocol, Flag flag)  {
        return srvCountMap.keySet().stream().filter(key -> key.startsWith("P="+protocol) && key.indexOf("DI="+dstIp) > -1 && (
                key.indexOf("F="+Flag.REJ) > -1
        )).mapToInt( key -> srvCountMap.get(key)).sum();
    }
    public double getDstHostRerrorRate(String dstIp, int dstPort, String srcIp, int srcPort,int protocol, Flag flag) {
        double dstHostCount = (double)this.getDstHostCount(dstIp, dstPort, protocol);
        double dstHostRerrorCount = (double)this.getDstHostRerrorCount(dstIp, protocol, flag);

        return dstHostCount == 0 ? 0 : dstHostCount < dstHostRerrorCount ? 1 : (dstHostRerrorCount / dstHostCount);
    }
    //41	Dst Host Srv Rerror Rate
    public int getDstHostSrvRerrorCount(int dstPort, int protocol, Flag flag)  {
        return srvCountMap.keySet().stream().filter(key -> key.startsWith("P="+protocol) &&  key.indexOf("DP="+dstPort) > -1 && (
                key.indexOf("F="+Flag.REJ) > -1
        )).mapToInt( key -> srvCountMap.get(key)).sum();
    }
    public double getDstHostSrvRerrorRate(String dstIp, int dstPort, String srcIp, int srcPort,int protocol, Flag flag) {
        double dstHostSameSrvCount = (double)this.getDstHostSameSrvCount(dstIp, dstPort, protocol);
        double dstHostSrvRerrorCount = (double)this.getDstHostSrvRerrorCount(dstPort, protocol, flag);

        return dstHostSameSrvCount == 0 ? 0 : dstHostSameSrvCount < dstHostSrvRerrorCount ? 1 : (dstHostSrvRerrorCount / dstHostSameSrvCount);
    }
}
