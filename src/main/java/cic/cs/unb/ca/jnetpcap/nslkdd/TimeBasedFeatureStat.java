package cic.cs.unb.ca.jnetpcap.nslkdd;

import net.jodah.expiringmap.ExpirationPolicy;
import net.jodah.expiringmap.ExpiringMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.concurrent.TimeUnit;

public class TimeBasedFeatureStat implements Runnable{
    public static final Logger logger = LoggerFactory.getLogger(TimeBasedFeatureStat.class);
    private Map<String, Integer> srvCountMap = null;
    private int checkDuration = 2;
    private long monitorPeriod = 1 * 10 * 1000L;

    public TimeBasedFeatureStat(int checkDuration) {
        this.checkDuration = checkDuration;

        srvCountMap = ExpiringMap.builder()
                .maxSize(10000)
                .expirationPolicy(ExpirationPolicy.CREATED)
                .expiration(this.checkDuration, TimeUnit.SECONDS)
                .build();
    }
    @Override
    public void run() {
        try {
            while( !Thread.interrupted() ) {
                logger.info("TimeBasedFeatureStat-srvCountMap count:" + srvCountMap.size());
                Thread.sleep(this.monitorPeriod);
            }
        } catch (InterruptedException e) {
            logger.error("",e);
            throw new RuntimeException(e);
        }
    }

    private String makeKey(String srdIp, int srcPort, String dstIp, int dstPort, int protocol, NSLKDDConst.conversation_state_t flag) {
        StringBuffer sb = new StringBuffer();

        sb.append("P").append("=").append(protocol);
        sb.append("SI").append("=").append(srdIp);
        sb.append("SP").append("=").append(srcPort);
        sb.append("DI").append("=").append(dstIp);
        sb.append("DP").append("=").append(dstPort);
        sb.append("F").append("=").append(flag);

        return sb.toString();
    }

    public void addConnection(String srcIp, int srcPort, String dstIp, int dstPort, int protocol, NSLKDDConst.conversation_state_t flag ) {

        String key = makeKey(srcIp, srcPort, dstIp, dstPort, protocol, flag);
        if( srvCountMap.containsKey(key) ) {
            int tmpCount = srvCountMap.get(key);
            srvCountMap.put(key, tmpCount+1);
        } else {
            srvCountMap.put(key, 1);
        }
    }
    public int getCount(String dstIp, int dstPort, int protocol) {
        return srvCountMap.keySet().stream().filter(key -> key.startsWith("P="+protocol) && key.indexOf("DI="+dstIp) > -1).mapToInt( key -> srvCountMap.get(key)).sum();
    }
    public int getSrvCount(String dstIp, int dstPort, int protocol) {
        return srvCountMap.keySet().stream().filter(key -> key.startsWith("P="+protocol) &&  key.indexOf("DP="+dstPort) > -1).mapToInt( key -> srvCountMap.get(key)).sum();
    }
    public int getSameSrvCount(String dstIp, int dstPort, int protocol) {
        return srvCountMap.keySet().stream().filter(key -> key.startsWith("P="+protocol) && key.indexOf("DI="+dstIp) > -1 && key.indexOf("DP="+dstPort) >  -1).mapToInt( key -> srvCountMap.get(key)).sum();
    }
    public double getSameSrvRate(String dstIp, int dstPort, int protocol) {
        double dstHostCount = (double)this.getCount(dstIp, dstPort, protocol);
        double dstHostSrvCount = (double)this.getSameSrvCount(dstIp, dstPort, protocol);

        logger.info("dstHostCount:{}, dstHostSrvCount{} rate{}", dstHostCount, dstHostSrvCount, dstHostCount == 0 ? 0 : dstHostCount < dstHostSrvCount ? 1 : (dstHostSrvCount / dstHostCount));
        return dstHostCount == 0 ? 0 : dstHostCount < dstHostSrvCount ? 1 : (dstHostSrvCount / dstHostCount);
    }
    public int getDiffSrvCount(String dstIp, int dstPort, int protocol) {
        return srvCountMap.keySet().stream().filter(key -> key.startsWith("P="+protocol) && key.indexOf("DI="+dstIp) > -1 && key.indexOf("DP="+dstPort)==-1).mapToInt( key -> srvCountMap.get(key)).sum();
    }
    public double getDiffSrvRate(String dstIp, int dstPort, int protocol) {
        int dstHostCount = this.getCount(dstIp, dstPort, protocol);
        int dstHostDiffSrvCount = this.getDiffSrvCount(dstIp, dstPort, protocol);

        return dstHostCount == 0 ? 0 : dstHostCount < dstHostDiffSrvCount ? 1 : (dstHostDiffSrvCount / dstHostCount);
    }
    public int getSrvDiffHostCount(String dstIp, int dstPort, String srcIp, int srcPort, int protocol) {
        return srvCountMap.keySet().stream().filter(key -> key.startsWith("P="+protocol) &&  key.indexOf("DP="+dstPort) > -1 && key.indexOf("DI="+dstIp)==-1).mapToInt( key -> srvCountMap.get(key)).sum();
    }
    public double getSrvDiffHostRate(String dstIp, int dstPort, String srcIp, int srcPort,int protocol) {
        int dstHostSameSrvCount = this.getSrvCount(dstIp, dstPort, protocol);
        int dstHostSrvDiffHostCount = this.getSrvDiffHostCount(dstIp, dstPort, srcIp, srcPort, protocol);

        return dstHostSameSrvCount == 0 ? 0 : dstHostSameSrvCount < dstHostSrvDiffHostCount ? 1 : (dstHostSrvDiffHostCount / dstHostSameSrvCount);
    }
    //38	Dst Host Serror Rate
    public int getSerrorCount(String dstIp, int protocol, NSLKDDConst.conversation_state_t flag)  {
        return srvCountMap.keySet().stream().filter(key -> key.startsWith("P="+protocol) && key.indexOf("DI="+dstIp) > -1 && (
                        key.indexOf("F="+NSLKDDConst.conversation_state_t.S0) > -1
                        || key.indexOf("F="+NSLKDDConst.conversation_state_t.S1) > -1
                        || key.indexOf("F="+NSLKDDConst.conversation_state_t.S2) > -1
                        || key.indexOf("F="+NSLKDDConst.conversation_state_t.S3) > -1
        )).mapToInt( key -> srvCountMap.get(key)).sum();
    }
    public double getSerrorRate(String dstIp, int dstPort, String srcIp, int srcPort,int protocol, NSLKDDConst.conversation_state_t flag) {
        int dstHostCount = this.getCount(dstIp, dstPort, protocol);
        int dstHostSerrorCount = this.getSerrorCount(dstIp, protocol, flag);

        return dstHostCount == 0 ? 0 : dstHostCount < dstHostSerrorCount ? 1 : (dstHostSerrorCount / dstHostCount);
    }
    //39	Dst Host Srv Serror Rate
    public int getSrvSerrorCount(int dstPort, int protocol, NSLKDDConst.conversation_state_t flag)  {
        return srvCountMap.keySet().stream().filter(key -> key.startsWith("P="+protocol) &&  key.indexOf("DP="+dstPort) > -1 && (
                key.indexOf("F="+NSLKDDConst.conversation_state_t.S0) > -1
                        || key.indexOf("F="+NSLKDDConst.conversation_state_t.S1) > -1
                        || key.indexOf("F="+NSLKDDConst.conversation_state_t.S2) > -1
                        || key.indexOf("F="+NSLKDDConst.conversation_state_t.S3) > -1
        )).mapToInt( key -> srvCountMap.get(key)).sum();
    }
    public double getSrvSerrorRate(String dstIp, int dstPort, String srcIp, int srcPort,int protocol, NSLKDDConst.conversation_state_t flag) {
        int dstHostSameSrvCount = this.getSrvCount(dstIp, dstPort, protocol);
        int dstHostSrvSerrorCount = this.getSrvSerrorCount(dstPort, protocol, flag);

        return dstHostSameSrvCount == 0 ? 0 : dstHostSameSrvCount < dstHostSrvSerrorCount ? 1 : (dstHostSrvSerrorCount / dstHostSameSrvCount);
    }
    //40	Dst Host Rerror Rate
    public int getRerrorCount(String dstIp, int protocol, NSLKDDConst.conversation_state_t flag)  {
        return srvCountMap.keySet().stream().filter(key -> key.startsWith("P="+protocol) && key.indexOf("DI="+dstIp) > -1 && (
                key.indexOf("F="+NSLKDDConst.conversation_state_t.REJ) > -1
        )).mapToInt( key -> srvCountMap.get(key)).sum();
    }
    public double getRerrorRate(String dstIp, int dstPort, String srcIp, int srcPort,int protocol, NSLKDDConst.conversation_state_t flag) {
        int dstHostCount = this.getCount(dstIp, dstPort, protocol);
        int dstHostRerrorCount = this.getRerrorCount(dstIp, protocol, flag);

        return dstHostCount == 0 ? 0 : dstHostCount < dstHostRerrorCount ? 1 : (dstHostRerrorCount / dstHostCount);
    }
    //41	Dst Host Srv Rerror Rate
    public int getSrvRerrorCount(int dstPort, int protocol, NSLKDDConst.conversation_state_t flag)  {
        return srvCountMap.keySet().stream().filter(key -> key.startsWith("P="+protocol) &&  key.indexOf("DP="+dstPort) > -1 && (
                key.indexOf("F="+NSLKDDConst.conversation_state_t.REJ) > -1
        )).mapToInt( key -> srvCountMap.get(key)).sum();
    }
    public double getSrvRerrorRate(String dstIp, int dstPort, String srcIp, int srcPort,int protocol, NSLKDDConst.conversation_state_t flag) {
        int dstHostSameSrvCount = this.getSrvCount(dstIp, dstPort, protocol);
        int dstHostSrvRerrorCount = this.getSrvRerrorCount(dstPort, protocol, flag);

        return dstHostSameSrvCount == 0 ? 0 : dstHostSameSrvCount < dstHostSrvRerrorCount ? 1 : (dstHostSrvRerrorCount / dstHostSameSrvCount);
    }
}
