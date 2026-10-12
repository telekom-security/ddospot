package persona

import "net/netip"

type timeServer struct {
	addr    netip.Addr
	stratum uint8
}

func ts(addr string, stratum uint8) timeServer {
	return timeServer{netip.MustParseAddr(addr), stratum}
}

// timeServers are public stratum 1 and 2 servers of national metrology
// institutes, universities, research networks and the NTP pool. Each one
// answered an SNTP query when the list was written (2026-10-11), the
// stratum is the one of its answer.
var timeServers = []timeServer{
	ts("192.53.103.108", 1),  // ptbtime1.ptb.de
	ts("192.53.103.104", 1),  // ptbtime2.ptb.de
	ts("192.53.103.103", 1),  // ptbtime3.ptb.de
	ts("194.94.95.123", 1),   // ptbtime4.ptb.de
	ts("129.6.15.28", 1),     // time-a-g.nist.gov
	ts("129.6.15.29", 1),     // time-b-g.nist.gov
	ts("129.6.15.30", 1),     // time-c-g.nist.gov
	ts("129.6.15.27", 1),     // time-d-g.nist.gov
	ts("132.163.97.1", 1),    // time-a-wwv.nist.gov
	ts("132.163.97.2", 1),    // time-b-wwv.nist.gov
	ts("132.163.97.3", 1),    // time-c-wwv.nist.gov
	ts("132.163.96.1", 1),    // time-a-b.nist.gov
	ts("132.163.96.2", 1),    // time-b-b.nist.gov
	ts("132.163.96.3", 1),    // time-c-b.nist.gov
	ts("192.5.41.40", 1),     // tick.usno.navy.mil
	ts("192.5.41.41", 1),     // tock.usno.navy.mil
	ts("131.188.3.221", 1),   // ntp1.fau.de
	ts("131.188.3.222", 1),   // ntp2.fau.de
	ts("131.188.3.223", 1),   // ntp3.fau.de
	ts("129.69.253.1", 1),    // rustime01.rus.uni-stuttgart.de
	ts("129.69.253.17", 1),   // rustime02.rus.uni-stuttgart.de
	ts("160.45.10.8", 1),     // zeit.fu-berlin.de
	ts("130.133.1.10", 1),    // time.fu-berlin.de
	ts("130.149.17.21", 1),   // ntps1-0.cs.tu-berlin.de
	ts("134.130.4.17", 1),    // ntp1.rwth-aachen.de
	ts("134.60.1.27", 2),     // ntp1.uni-ulm.de
	ts("134.60.111.110", 2),  // ntp2.uni-ulm.de
	ts("131.234.220.231", 1), // time1.uni-paderborn.de
	ts("129.187.254.32", 1),  // ntp1.lrz.de
	ts("141.84.9.197", 1),    // ntp3.lrz.de
	ts("195.176.26.206", 1),  // time.metas.ch
	ts("195.176.26.215", 1),  // ntp.metas.ch
	ts("195.176.26.204", 1),  // ntp11.metas.ch
	ts("195.176.26.205", 1),  // ntp12.metas.ch
	ts("193.204.114.232", 1), // ntp1.inrim.it
	ts("193.204.114.233", 1), // ntp2.inrim.it
	ts("133.243.238.163", 1), // ntp.nict.jp
	ts("133.243.238.164", 1), // ntp.nict.jp
	ts("133.243.238.243", 1), // ntp.nict.jp
	ts("133.243.238.244", 1), // ntp.nict.jp
	ts("61.205.120.130", 1),  // ntp.nict.jp
	ts("210.173.160.27", 2),  // ntp1.jst.mfeed.ad.jp
	ts("210.173.160.57", 2),  // ntp2.jst.mfeed.ad.jp
	ts("210.173.160.87", 2),  // ntp3.jst.mfeed.ad.jp
	ts("194.58.202.20", 1),   // sth1.ntp.se
	ts("194.58.202.148", 1),  // sth2.ntp.se
	ts("194.58.203.20", 1),   // gbg1.ntp.se
	ts("194.58.203.148", 1),  // gbg2.ntp.se
	ts("194.58.204.20", 1),   // mmo1.ntp.se
	ts("194.58.204.148", 1),  // mmo2.ntp.se
	ts("194.58.206.20", 1),   // lul1.ntp.se
	ts("194.58.206.148", 1),  // lul2.ntp.se
	ts("194.58.205.20", 1),   // svl1.ntp.se
	ts("194.58.205.148", 1),  // svl2.ntp.se
	ts("217.31.202.100", 1),  // ntp.nic.cz
	ts("195.113.144.201", 1), // tik.cesnet.cz
	ts("89.109.251.21", 1),   // ntp1.vniiftri.ru
	ts("89.109.251.22", 1),   // ntp2.vniiftri.ru
	ts("94.198.159.10", 1),   // ntp.time.nl
	ts("31.223.173.226", 1),  // ntp.vsl.nl
	ts("192.171.1.150", 1),   // time.esa.int
	ts("193.190.230.105", 2), // ntp1.oma.be
	ts("193.190.230.106", 2), // ntp2.oma.be
	ts("145.238.80.83", 2),   // ntp.obspm.fr
	ts("145.238.80.80", 1),   // ntp-p1.obspm.fr
	ts("193.0.0.229", 1),     // ntp.ripe.net
	ts("131.246.1.116", 2),   // ntp.uni-kl.de
	ts("131.246.9.116", 2),   // ntp.uni-kl.de
	ts("139.143.5.30", 1),    // ntp1.npl.co.uk
	ts("139.143.5.31", 1),    // ntp2.npl.co.uk
	ts("193.62.22.74", 1),    // ntp1.ja.net
	ts("132.246.11.227", 2),  // time.nrc.ca
	ts("132.246.11.229", 2),  // time.nrc.ca
	ts("132.246.11.237", 2),  // time.nrc.ca
	ts("132.246.11.238", 2),  // time.nrc.ca
	ts("209.87.233.53", 2),   // time.chu.nrc.ca
	ts("209.87.233.54", 2),   // time.chu.nrc.ca
	ts("131.111.8.35", 2),    // ntp0.cam.ac.uk
	ts("131.111.8.8", 2),     // ntp1.cam.ac.uk
	ts("213.239.239.164", 2), // ntp1.hetzner.de
	ts("213.239.239.165", 2), // ntp2.hetzner.de
	ts("213.239.239.166", 2), // ntp3.hetzner.de
	ts("18.7.33.13", 2),      // time.mit.edu
	ts("132.239.1.6", 1),     // ntp.ucsd.edu
	ts("169.229.128.134", 1), // ntp1.net.berkeley.edu
	ts("169.229.128.142", 1), // ntp2.net.berkeley.edu
	ts("176.9.157.12", 2),    // ntp.dianacht.de
	ts("134.76.249.102", 1),  // ntp1.gwdg.de
	ts("158.227.98.15", 1),   // ntp.i2t.ehu.eus
	ts("150.214.94.5", 1),    // hora.roa.es
	ts("150.214.94.10", 1),   // minuto.roa.es
	ts("118.143.17.83", 1),   // time.hko.hk
	ts("14.139.60.103", 1),   // time.nplindia.org
	ts("14.139.60.107", 1),   // time.nplindia.org
	ts("200.160.7.186", 1),   // a.st1.ntp.br
	ts("186.192.158.147", 1), // c.st1.ntp.br
	ts("200.25.72.83", 1),    // c.st1.ntp.br
	ts("200.20.186.76", 1),   // d.st1.ntp.br
	ts("200.160.7.193", 1),   // gps.ntp.br
	ts("200.160.7.197", 1),   // gps.ntp.br
	// members of the NTP pool
	ts("192.33.96.102", 1),   // 0.ch.pool.ntp.org
	ts("162.55.190.98", 2),   // 0.de.pool.ntp.org
	ts("188.68.34.173", 2),   // 1.de.pool.ntp.org
	ts("168.119.211.223", 2), // 2.de.pool.ntp.org
	ts("217.91.44.17", 2),    // 2.de.pool.ntp.org
	ts("185.216.176.59", 2),  // 3.de.pool.ntp.org
	ts("152.53.132.244", 2),  // 0.at.pool.ntp.org
	ts("194.177.151.10", 2),  // 0.at.pool.ntp.org
	ts("66.42.71.197", 2),    // 0.us.pool.ntp.org
	ts("23.157.160.168", 2),  // 1.us.pool.ntp.org
	ts("147.78.228.41", 2),   // 0.se.pool.ntp.org
	ts("171.25.158.11", 2),   // 0.se.pool.ntp.org
}
