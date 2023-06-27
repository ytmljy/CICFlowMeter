package cic.cs.unb.ca.jnetpcap.nslkdd;


import org.apache.commons.lang3.math.NumberUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

public enum NSLKDDFlowFeature {

    lable("Lable","Lable"),					//1 Lable
    duration("Dutation","duration"),			//2
    protocol_type("Protocol Type","protocol_type"),				//3
    service("Service","Service"),					//4
    flag("Flag","flag"),				//5
    src_bytes("Src Bytes","src_bytes"),					//6
    dst_bytes("Dst Bytes","dst_bytes"),					//7
    land("Land","Land"),				//8
    wrong_gragment("Wrong Fragment","wrong_gragment"),				//9
    urgent("Urgent","urgent"),			//10
    hot("Hot","hot"),		//11
    num_failed_logins("Num Failed Logins","num_failed_logins"),
    logged_in("Logged In","logged_in"),
    num_compromised("Num Compromised","num_compromised"),
    root_shell("Root Shell","root_shell"),
    su_attempted("Su Attempted","su_attempted"),
    num_root("Num Root","num_root"),
    num_file_creations("Num File Creations","num_file_creations"),
    num_shells("Num Shells","num_shells"),
    num_access_files("Num Access Files","num_access_files"),
    num_outbound_cmds("Num Outbound Cmds","num_outbound_cmds"),
    is_hot_logins("Is Hot Logins","is_hot_logins"),
    is_guest_login("Is Guest Login","is_guest_login"),
    count("Count","count"),
    srv_count("Srv Count","srv_count"),
    serror_rate("Serror Rate","serror_rate"),
    srv_serror_rate("Srv Serror Rate","srv_serror_rate"),
    rerror_rate("Rerror Rate","rerror_rate"),
    srv_rerror_rate("Srv Rerror Rate","srv_rerror_rate"),
    same_srv_rate("Same Srv Rate","same_srv_rate"),
    diff_srv_rate("Diff Srv Rate","diff_srv_rate"),
    srv_diff_host_rate("Srv Diff Host Rate","srv_diff_host_rate"),
    dst_host_count("Dst Host Count","dst_host_count"),
    dst_host_srv_count("Dst Host Srv Count","dst_host_srv_count"),
    dst_host_same_srv_rate("Dst Host Same Srv Rate","dst_host_same_srv_rate"),
    dst_host_diff_srv_rate("Dst Host Diff Srv Rate","dst_host_diff_srv_rate"),
    dst_host_same_src_port_rate("Dst Host Same Src Port Rate","dst_host_same_src_port_rate"),
    dst_host_srv_diff_host_rate("Dst Host Srv Diff Host Rate","dst_host_srv_diff_host_rate"),
    dst_host_serror_rate("Dst Host Serror Rate","dst_host_serror_rate"),
    dst_host_srv_serror_rate("Dst Host Srv Serror Rate","dst_host_srv_serror_rate"),
    dst_host_rerror_rate("Dst Host Rerror Rate","dst_host_rerror_rate"),
    dst_host_srv_rerror_rate("Dst Host Srv Rerror Rate","dst_host_srv_rerror_rate");

    protected static final Logger logger = LoggerFactory.getLogger(NSLKDDFlowFeature.class);
	private static String HEADER;
	private String name;
	private String abbr;
	private boolean isNumeric;
	private String[] values;

    NSLKDDFlowFeature(String name, String abbr, boolean numeric) {
        this.name = name;
        this.abbr = abbr;
        isNumeric = numeric;
    }

	NSLKDDFlowFeature(String name, String abbr) {
        this.name = name;
        this.abbr = abbr;
        isNumeric = true;

    }

	NSLKDDFlowFeature(String name, String abbr, String[] values) {
		this.name = name;
        this.abbr = abbr;
        this.values = values;
        isNumeric = false;
    }

	public String getName() {
		return name;
	}

    public String getAbbr() {
        return abbr;
    }

    public boolean isNumeric(){
        return isNumeric;
    }

	public static NSLKDDFlowFeature getByName(String name) {
		for(NSLKDDFlowFeature feature: NSLKDDFlowFeature.values()) {
			if(feature.getName().equals(name)) {
				return feature;
			}
		}
		return null;
	}
	
	public static String getHeader() {
		
		if(HEADER ==null|| HEADER.length()==0) {
			StringBuilder header = new StringBuilder();
			
			for(NSLKDDFlowFeature feature: NSLKDDFlowFeature.values()) {
				header.append(feature.getName()).append(",");
			}
			header.deleteCharAt(header.length()-1);
			HEADER = header.toString();
		}
		return HEADER;
	}

	@Override
	public String toString() {
		return name;
	}
	
}
