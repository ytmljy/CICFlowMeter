package cic.cs.unb.ca.jnetpcap.nslkdd;

import cic.cs.unb.ca.flow.FlowMgr;
import cic.cs.unb.ca.jnetpcap.BasicFlow;
import cic.cs.unb.ca.jnetpcap.FlowGenerator;
import cic.cs.unb.ca.jnetpcap.PacketReader;
import cic.cs.unb.ca.jnetpcap.worker.FlowGenListener;
import cic.cs.unb.ca.jnetpcap.worker.InsertCsvRow;
import org.jnetpcap.Pcap;
import org.jnetpcap.nio.JMemory.Type;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.swing.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

public class NSLKDDTrafficFlowWorker implements FlowGenListener, Runnable {

	public static final Logger logger = LoggerFactory.getLogger(NSLKDDTrafficFlowWorker.class);
    public static final String PROPERTY_FLOW = "NSLKDD";
	private String device;
    private String filePath;
    private String fileName;
    int cnt = 0;


    public NSLKDDTrafficFlowWorker(String device) {
		super();
		this.device = device;
        filePath = "./out";
        fileName = PROPERTY_FLOW + "_" + LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMddHHmmss"));
	}

	public void run() {
		
		FlowGenerator   flowGen = new FlowGenerator(true,120000000L, 5000000L);
		flowGen.addFlowListener(this);
		int snaplen = 64 * 1024;//2048; // Truncate packet at this size
		int promiscous = Pcap.MODE_PROMISCUOUS;
		int timeout = 60 * 1000; // In milliseconds
		StringBuilder errbuf = new StringBuilder();
		Pcap pcap = Pcap.openLive(device, snaplen, promiscous, timeout, errbuf);
		if (pcap == null) {
			logger.info("open {} fail -> {}",device,errbuf.toString());
            return;
		}

		PcapPacketHandler<String> jpacketHandler = (packet, user) -> {

            /*
             * BufferUnderflowException while decoding header
             * that is because:
             * 1.PCAP library is not multi-threaded
             * 2.jNetPcap library is not multi-threaded
             * 3.Care must be taken how packets or the data they referenced is used in multi-threaded environment
             *
             * typical rule:
             * make new packet objects and perform deep copies of the data in PCAP buffers they point to
             *
             * but it seems not work
             */

            PcapPacket permanent = new PcapPacket(Type.POINTER);
            packet.transferStateAndDataTo(permanent);

            flowGen.addPacket(PacketReader.getBasicPacketInfo(permanent, true, false));
        };

        //FlowMgr.getInstance().setListenFlag(true);
        logger.info("Pcap is listening...");
        int ret = pcap.loop(Pcap.DISPATCH_BUFFER_FULL, jpacketHandler, device);

		String str;
        switch (ret) {
            case 0:
                str = "listening: " + device + " finished";
                break;
            case -1:
                str = "listening: " + device + " error";
                break;
            case -2:
                str = "stop listening: " + device;
                break;
                default:
                    str = String.valueOf(ret);
        }
	}

	@Override
	public void onFlowGenerated(BasicFlow flow) {
        String flowDump = flow.dumpFlowBasedFeaturesNSLKDD();
        List<String> flowStringList = new ArrayList<>();
        flowStringList.add(flowDump);
        InsertCsvRow.insert(NSLKDDFlowFeature.getHeader(),flowStringList, filePath,fileName+ FlowMgr.FLOW_SUFFIX);
        cnt++;
        String console = String.format("%s -> %d flows \r", fileName,cnt);
        System.out.print(console);
	}
}
