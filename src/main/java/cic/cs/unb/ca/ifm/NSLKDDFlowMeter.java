package cic.cs.unb.ca.ifm;

import cic.cs.unb.ca.flow.FlowMgr;
import cic.cs.unb.ca.jnetpcap.BasicFlow;
import cic.cs.unb.ca.jnetpcap.BasicPacketInfo;
import cic.cs.unb.ca.jnetpcap.FlowGenerator;
import cic.cs.unb.ca.jnetpcap.PacketReader;
import cic.cs.unb.ca.jnetpcap.nslkdd.NSLKDDFlowFeature;
import cic.cs.unb.ca.jnetpcap.nslkdd.NSLKDDTrafficFlowWorker;
import cic.cs.unb.ca.jnetpcap.worker.FlowGenListener;
import cic.cs.unb.ca.jnetpcap.worker.InsertCsvRow;
import org.apache.commons.io.FilenameUtils;
import org.jnetpcap.PcapClosedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import swing.common.SwingUtils;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import static cic.cs.unb.ca.Sys.FILE_SEP;


public class NSLKDDFlowMeter {

    public static final Logger logger = LoggerFactory.getLogger(NSLKDDFlowMeter.class);
    private static final String DividingLine = "-------------------------------------------------------------------------------";
    private static String[] animationChars = new String[]{"|", "/", "-", "\\"};

    public static void main(String[] args) {

        long flowTimeout = 120000000L;
        long activityTimeout = 5000000L;
        String rootPath = System.getProperty("user.dir");
        String netIf;
        String outPath;

        if (args.length < 1) {
            logger.info("Please select network interface");
            return;
        }
        netIf = args[0];
        logger.info("You select network interface: {}", netIf);

        NSLKDDTrafficFlowWorker flowWorker = new NSLKDDTrafficFlowWorker(netIf);
        Thread flowWorkerThread = new Thread(flowWorker);
        flowWorkerThread.start();
    }

}
