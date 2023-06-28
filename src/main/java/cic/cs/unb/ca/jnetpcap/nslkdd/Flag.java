package cic.cs.unb.ca.jnetpcap.nslkdd;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public enum Flag {

    /**
     * Conversatiov states
     *	- INIT & SF for all protocols except TCP
     *	- other states specific to TCP
     * Description from https://www.bro.org/sphinx/scripts/base/protocols/conn/main.bro.html
     */
    OTH ("OTH ", 0),
    INIT ("INIT ", 0),
    S4 ("S4 ", 0),
    REJ ("REJ ", 1),
    RSTO ("RSTO ", 2),
    RSTOS0("RSTOS0", 3),
    RSTR ("RSTR ", 4),
    RSTRH ("RSTRH ", 4),
    S0 ("S0 ", 5),
    S1 ("S1 ", 6),
    ESTAB ("ESTAB ", 6),
    S2 ("S2 ", 7),
    S2F ("S2F ", 7),
    S3 ("S3 ", 8),
    S3F ("S3F ", 8),
    SF ("SF ", 9),
    SH ("SH ", 10),
    SHR ("SHR ", 10)
    ;


	protected static final Logger logger = LoggerFactory.getLogger(Flag.class);
	private static String HEADER;
	private String name;
	private int code;

    Flag(String name, int code) {
        this.name = name;
        this.code = code;
    }

	public String getName() {
		return name;
	}

    public int getCode() {
        return code;
    }

	public static Flag getByName(String name) {
		for(Flag feature: Flag.values()) {
			if(feature.getName().equals(name)) {
				return feature;
			}
		}
		return null;
	}

	@Override
	public String toString() {
		return name;
	}
	
}
