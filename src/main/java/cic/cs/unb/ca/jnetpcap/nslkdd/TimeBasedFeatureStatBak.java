package cic.cs.unb.ca.jnetpcap.nslkdd;

import java.util.Iterator;
import java.util.concurrent.ConcurrentHashMap;

public class TimeBasedFeatureStatBak implements Runnable{

    private ConcurrentHashMap<String, Integer> countMap = new ConcurrentHashMap<>();
    private ConcurrentHashMap<String, Integer> srvCountMap = new ConcurrentHashMap<>();
    private ConcurrentHashMap<String, Integer> serrorRateMap = new ConcurrentHashMap<>();
    private ConcurrentHashMap<String, Integer> srvSerrorRateMap = new ConcurrentHashMap<>();
    private ConcurrentHashMap<String, Integer> rerrorRateMap = new ConcurrentHashMap<>();
    private ConcurrentHashMap<String, Integer> srvRerrorRateMap = new ConcurrentHashMap<>();
    private ConcurrentHashMap<String, Integer> srvMap = new ConcurrentHashMap<>();
    private long sleepTime = 2 * 1000;

    public TimeBasedFeatureStatBak(int sleepTimeSecond) {
        this.sleepTime = sleepTimeSecond * 1000;
    }
    @Override
    public void run() {

        countMap.clear();
        srvCountMap.clear();
        serrorRateMap.clear();
        srvSerrorRateMap.clear();
        rerrorRateMap.clear();
        srvRerrorRateMap.clear();
        srvMap.clear();

        try {
            Thread.sleep(this.sleepTime);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

    public void addConnection(String dstIp, int dstPort, int protocol, NSLKDDConst.service_t service) {

        if( countMap.containsKey(dstIp + "_" + protocol) ) {
            int tmpCount = countMap.get(dstIp + "_" + protocol);
            countMap.put(dstIp + "_" + protocol, tmpCount+1);
        } else {
            countMap.put(dstIp + "_" + protocol, 1);
        }

        if( srvCountMap.containsKey(dstPort + "_" + protocol) ) {
            int tmpCount = srvCountMap.get(dstPort + "_" + protocol);
            srvCountMap.put(dstPort + "_" + protocol, tmpCount+1);
        } else {
            srvCountMap.put(dstPort + "_" + protocol, 1);
        }

        if( srvMap.containsKey(dstIp + "_" + service) ) {
            int tmpCount = srvMap.get(dstIp + "_" + service);
            srvMap.put(dstIp + "_" + service, tmpCount+1);
        } else {
            srvMap.put(dstIp + "_" + service, 1);
        }
    }

    public void addFlag(String dstIp, int dstPort, int protocol, NSLKDDConst.conversation_state_t flag) {

        if( flag == NSLKDDConst.conversation_state_t.S0
                || flag == NSLKDDConst.conversation_state_t.S1
                || flag == NSLKDDConst.conversation_state_t.S2
                || flag == NSLKDDConst.conversation_state_t.S3
        )  {
            if( serrorRateMap.containsKey(dstIp + "_" + protocol) ) {
                int tmpCount = serrorRateMap.get(dstIp + "_" + protocol);
                serrorRateMap.put(dstIp + "_" + protocol, tmpCount+1);
            } else {
                serrorRateMap.put(dstIp + "_" + protocol, 1);
            }

            if( srvSerrorRateMap.containsKey(dstPort + "_" + protocol) ) {
                int tmpCount = srvSerrorRateMap.get(dstPort + "_" + protocol);
                srvSerrorRateMap.put(dstPort + "_" + protocol, tmpCount+1);
            } else {
                srvSerrorRateMap.put(dstPort + "_" + protocol, 1);
            }
        } else if( flag == NSLKDDConst.conversation_state_t.REJ ) {
            if( rerrorRateMap.containsKey(dstIp + "_" + protocol) ) {
                int tmpCount = rerrorRateMap.get(dstIp + "_" + protocol);
                rerrorRateMap.put(dstIp + "_" + protocol, tmpCount+1);
            } else {
                rerrorRateMap.put(dstIp + "_" + protocol, 1);
            }

            if( srvRerrorRateMap.containsKey(dstPort + "_" + protocol) ) {
                int tmpCount = srvRerrorRateMap.get(dstPort + "_" + protocol);
                srvRerrorRateMap.put(dstPort + "_" + protocol, tmpCount+1);
            } else {
                srvRerrorRateMap.put(dstPort + "_" + protocol, 1);
            }
        } else {

        }
    }

    public int getCount(String dstIp, int protocol) {
        if( countMap.containsKey(dstIp + "_" + protocol) ) {
            return  countMap.get(dstIp + "_" + protocol);
        } else {
            return 0;
        }
    }

    public int getSrvCount(String dstIp, int dstPort, int protocol) {
        if( srvCountMap.containsKey(dstIp + "_" + dstPort + "_" + protocol) ) {
            return srvCountMap.get(dstIp + "_" + dstPort + "_" + protocol);
        } else {
            return 0;
        }
    }

    public int getSerrorCount(String dstIp, int protocol) {
        if( serrorRateMap.containsKey(dstIp + "_" + protocol) ) {
            return  serrorRateMap.get(dstIp + "_" + protocol);
        } else {
            return 0;
        }
    }

    public int getSrvSerrorCount(String dstIp, int dstPort, int protocol) {
        if( srvSerrorRateMap.containsKey(dstPort + "_" + protocol) ) {
            return srvSerrorRateMap.get(dstPort + "_" + protocol);
        } else {
            return 0;
        }
    }

    public float getSerrorRate(String dstIp, int protocol) {
        int totalCount = this.getCount(dstIp, protocol );
        int serrorCount = this.getSerrorCount(dstIp, protocol );

        if( totalCount == 0 )
            return 0;
        else
            return serrorCount / totalCount;
    }

    public float getSrvSerrorRate(String dstIp, int dstPort, int protocol) {
        int totalCount = this.getSrvCount(dstIp, dstPort, protocol );
        int serrorCount = this.getSrvSerrorCount(dstIp, dstPort,  protocol );

        if( totalCount == 0 )
            return 0;
        else
            return serrorCount / totalCount;
    }

    public int getRerrorCount(String dstIp, int protocol) {
        if( rerrorRateMap.containsKey(dstIp + "_" + protocol) ) {
            return rerrorRateMap.get(dstIp + "_" + protocol);
        } else {
            return 0;
        }
    }

    public int getSrvRerrorCount(String dstIp, int dstPort, int protocol) {
        if( srvRerrorRateMap.containsKey(dstPort + "_" + protocol) ) {
            return srvRerrorRateMap.get(dstPort + "_" + protocol);
        } else {
            return 0;
        }
    }

    public float getRerrorRate(String dstIp, int protocol) {
        int totalCount = this.getCount(dstIp, protocol );
        int rerrorCount = this.getRerrorCount(dstIp, protocol );

        if( totalCount == 0 )
            return 0;
        else
            return rerrorCount / totalCount;
    }

    public float getSrvRerrorRate(String dstIp, int dstPort, int protocol) {
        int totalCount = this.getSrvCount(dstIp, dstPort, protocol );
        int rerrorCount = this.getSrvRerrorCount(dstIp, dstPort,  protocol );

        if( totalCount == 0 )
            return 0;
        else
            return rerrorCount / totalCount;
    }

    public int getTotalSrvCount(String dstIp, NSLKDDConst.service_t service) {

        Iterator<String> iter = srvMap.keySet().iterator();

        int totalCount = 0;
        while( iter.hasNext() ) {
            String key = iter.next();
            if( key.startsWith(dstIp) ) {
                totalCount = totalCount + srvMap.get(key);
            }
        }

        return totalCount;
    }
    public int getSameSrvCount(String dstIp, NSLKDDConst.service_t service) {
        if( srvMap.containsKey(dstIp + "_" + service) ) {
            return srvMap.get(dstIp + "_" + service);
        } else {
            return 0;
        }
    }
    public float getSameSrvRate(String dstIp, int dstPort, int protocol, NSLKDDConst.service_t service) {
        int totalCount = this.getTotalSrvCount(dstIp, service);
        int sameSrvCount = this.getSameSrvCount(dstIp, service );

        if( totalCount == 0 )
            return 0;
        else
            return sameSrvCount / totalCount;
    }

    public float getDiffSrvRate(String dstIp, int dstPort, int protocol, NSLKDDConst.service_t service) {
        int totalCount = this.getTotalSrvCount(dstIp, service);
        int sameSrvCount = this.getSameSrvCount(dstIp, service );

        if( totalCount == 0 )
            return 0;
        else
            return (totalCount - sameSrvCount) / totalCount;
    }

    public float getSrvDiffHostRate(String dstIp, int dstPort, int protocol, NSLKDDConst.service_t service) {

        Iterator<String> iter = srvMap.keySet().iterator();

        int totalCount = 0;
        int diffHostCount = 0;
        while( iter.hasNext() ) {
            String key = iter.next();
            if( key.indexOf(service+"") > -1) {
                totalCount = totalCount + srvMap.get(key);
                if( !key.startsWith(dstIp) ) {
                    diffHostCount = diffHostCount + srvMap.get(key);
                }
            }
        }

        if( totalCount == 0 )
            return 0;
        else
            return diffHostCount / totalCount;
    }
}
