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

    public synchronized void addConnection(String srcIp, int srcPort, String dstIp, int dstPort, int protocol, Flag flag ) {

        String key = makeKey(srcIp, srcPort, dstIp, dstPort, protocol, flag);
        if( srvCountMap.containsKey(key) ) {
            int tmpCount = srvCountMap.get(key);
            srvCountMap.put(key, tmpCount+1);
        } else {
            srvCountMap.put(key, 1);
        }
    }
    public synchronized int getCount(String dstIp, int dstPort, int protocol) {
        return srvCountMap.keySet().stream().filter(key -> key.startsWith("P="+protocol) && key.indexOf("DI="+dstIp) > -1).mapToInt( key -> srvCountMap.get(key)).sum();
    }
    public synchronized  int getSrvCount(String dstIp, int dstPort, int protocol) {
        return srvCountMap.keySet().stream().filter(key -> key.startsWith("P="+protocol) &&  key.indexOf("DP="+dstPort) > -1).mapToInt( key -> srvCountMap.get(key)).sum();
    }
    public synchronized  int getSameSrvCount(String dstIp, int dstPort, int protocol) {
        return srvCountMap.keySet().stream().filter(key -> key.startsWith("P="+protocol) && key.indexOf("DI="+dstIp) > -1 && key.indexOf("DP="+dstPort) >  -1).mapToInt( key -> srvCountMap.get(key)).sum();
    }
    public synchronized double getSameSrvRate(String dstIp, int dstPort, int protocol) {
        double dstHostCount = (double)this.getCount(dstIp, dstPort, protocol);
        double dstHostSrvCount = (double)this.getSameSrvCount(dstIp, dstPort, protocol);

        return dstHostCount == 0 ? 0 : dstHostCount < dstHostSrvCount ? 1 : (dstHostSrvCount / dstHostCount);
    }
    public synchronized int getDiffSrvCount(String dstIp, int dstPort, int protocol) {
        return srvCountMap.keySet().stream().filter(key -> key.startsWith("P="+protocol) && key.indexOf("DI="+dstIp) > -1 && key.indexOf("DP="+dstPort)==-1).mapToInt( key -> srvCountMap.get(key)).sum();
    }
    public synchronized double getDiffSrvRate(String dstIp, int dstPort, int protocol) {
        double dstHostCount = (double)this.getCount(dstIp, dstPort, protocol);
        double dstHostDiffSrvCount = (double)this.getDiffSrvCount(dstIp, dstPort, protocol);

        return dstHostCount == 0 ? 0 : dstHostCount < dstHostDiffSrvCount ? 1 : (dstHostDiffSrvCount / dstHostCount);
    }
    public synchronized int getSrvDiffHostCount(String dstIp, int dstPort, String srcIp, int srcPort, int protocol) {
        return srvCountMap.keySet().stream().filter(key -> key.startsWith("P="+protocol) &&  key.indexOf("DP="+dstPort) > -1 && key.indexOf("DI="+dstIp)==-1).mapToInt( key -> srvCountMap.get(key)).sum();
    }
    public synchronized double getSrvDiffHostRate(String dstIp, int dstPort, String srcIp, int srcPort,int protocol) {
        double dstHostSameSrvCount = (double)this.getSrvCount(dstIp, dstPort, protocol);
        double dstHostSrvDiffHostCount = (double)this.getSrvDiffHostCount(dstIp, dstPort, srcIp, srcPort, protocol);

        return dstHostSameSrvCount == 0 ? 0 : dstHostSameSrvCount < dstHostSrvDiffHostCount ? 1 : (dstHostSrvDiffHostCount / dstHostSameSrvCount);
    }
    //38	Dst Host Serror Rate
    public synchronized int getSerrorCount(String dstIp, int protocol, Flag flag)  {
        return srvCountMap.keySet().stream().filter(key -> key.startsWith("P="+protocol) && key.indexOf("DI="+dstIp) > -1 && (
                        key.indexOf("F="+Flag.S0) > -1
                        || key.indexOf("F="+Flag.S1) > -1
                        || key.indexOf("F="+Flag.S2) > -1
                        || key.indexOf("F="+Flag.S3) > -1
        )).mapToInt( key -> srvCountMap.get(key)).sum();
    }
    public double getSerrorRate(String dstIp, int dstPort, String srcIp, int srcPort,int protocol, Flag flag) {
        double dstHostCount = (double)this.getCount(dstIp, dstPort, protocol);
        double dstHostSerrorCount = (double)this.getSerrorCount(dstIp, protocol, flag);

        return dstHostCount == 0 ? 0 : dstHostCount < dstHostSerrorCount ? 1 : (dstHostSerrorCount / dstHostCount);
    }
    //39	Dst Host Srv Serror Rate
    public synchronized int getSrvSerrorCount(int dstPort, int protocol, Flag flag)  {
        return srvCountMap.keySet().stream().filter(key -> key.startsWith("P="+protocol) &&  key.indexOf("DP="+dstPort) > -1 && (
                key.indexOf("F="+Flag.S0) > -1
                        || key.indexOf("F="+Flag.S1) > -1
                        || key.indexOf("F="+Flag.S2) > -1
                        || key.indexOf("F="+Flag.S3) > -1
        )).mapToInt( key -> srvCountMap.get(key)).sum();
    }
    public double getSrvSerrorRate(String dstIp, int dstPort, String srcIp, int srcPort,int protocol, Flag flag) {
        double dstHostSameSrvCount = (double)this.getSrvCount(dstIp, dstPort, protocol);
        double dstHostSrvSerrorCount = (double)this.getSrvSerrorCount(dstPort, protocol, flag);

        return dstHostSameSrvCount == 0 ? 0 : dstHostSameSrvCount < dstHostSrvSerrorCount ? 1 : (dstHostSrvSerrorCount / dstHostSameSrvCount);
    }
    //40	Dst Host Rerror Rate
    public synchronized int getRerrorCount(String dstIp, int protocol, Flag flag)  {
        return srvCountMap.keySet().stream().filter(key -> key.startsWith("P="+protocol) && key.indexOf("DI="+dstIp) > -1 && (
                key.indexOf("F="+Flag.REJ) > -1
        )).mapToInt( key -> srvCountMap.get(key)).sum();
    }
    public double getRerrorRate(String dstIp, int dstPort, String srcIp, int srcPort,int protocol, Flag flag) {
        double dstHostCount = (double)this.getCount(dstIp, dstPort, protocol);
        double dstHostRerrorCount = (double)this.getRerrorCount(dstIp, protocol, flag);

        return dstHostCount == 0 ? 0 : dstHostCount < dstHostRerrorCount ? 1 : (dstHostRerrorCount / dstHostCount);
    }
    //41	Dst Host Srv Rerror Rate
    public synchronized int getSrvRerrorCount(int dstPort, int protocol, Flag flag)  {
        return srvCountMap.keySet().stream().filter(key -> key.startsWith("P="+protocol) &&  key.indexOf("DP="+dstPort) > -1 && (
                key.indexOf("F="+Flag.REJ) > -1
        )).mapToInt( key -> srvCountMap.get(key)).sum();
    }
    public double getSrvRerrorRate(String dstIp, int dstPort, String srcIp, int srcPort,int protocol, Flag flag) {
        double dstHostSameSrvCount = (double)this.getSrvCount(dstIp, dstPort, protocol);
        double dstHostSrvRerrorCount = (double)this.getSrvRerrorCount(dstPort, protocol, flag);

        return dstHostSameSrvCount == 0 ? 0 : dstHostSameSrvCount < dstHostSrvRerrorCount ? 1 : (dstHostSrvRerrorCount / dstHostSameSrvCount);
    }
}
