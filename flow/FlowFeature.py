class FlowFeatures:
    def __init__(self):
        self.dest_port = 0
        self.flow_duration = 0

        self.bwd_packet_len_max = 0
        self.bwd_packet_len_min = 0
        self.bwd_packet_len_mean = 0
        self.bwd_packet_len_std = 0

        self.flow_IAT_mean = 0
        self.flow_IAT_std = 0
        self.flow_IAT_max = 0
        self.flow_IAT_min = 0

        self.fwd_IAT_total = 0
        self.fwd_IAT_mean = 0
        self.fwd_IAT_std = 0
        self.fwd_IAT_max = 0
        self.fwd_IAT_min = 0

        self.bwd_IAT_total = 0
        self.bwd_IAT_mean = 0
        self.bwd_IAT_std = 0
        self.bwd_IAT_max = 0
        self.bwd_IAT_min = 0

        self.fwd_PSH_flags = 0

        self.fwd_packets_s = 0

        self.max_packet_len = 0
        self.packet_len_mean = 0#have: 74, want 66.5
        self.packet_len_std = 0#have: 100, want 99.00183653
        self.packet_len_var = 0#have: 10045, want 9801.363636

        self.FIN_flag_count = 0 #have 1, want 0
        self.SYN_flag_count = 0 #have 1, want 0
        self.PSH_flag_count = 0 #have 1 want 0
        self.ACK_flag_count = 0
        self.URG_flag_count = 0

        self.avg_packet_size = 0#have: 74, want 72.54545455

        self.avg_bwd_segment_size = 0

        #default to -1
        self.init_win_bytes_forward = -1
        self.init_win_bytes_backward = -1#have: 8192, want 2053

        self.active_min = 0

        self.idle_mean = 0
        self.idle_std = 0
        self.idle_max = 0
        self.idle_min = 0

        self.src = ""
        self.dest = ""
        self.src_port = 0
        # self.dest_port = 0
        self.protocol = ''
        self.timestamp = 0

        self.pid = -1
        self.p_name = 'Not found'

    def getDestPort(self):
        return self.dest_port

    def setDestPort(self, value):
        self.dest_port = value

    def getFlowDuration(self):
        return self.flow_duration

    def setFlowDuration(self, value):
        self.flow_duration = int(round(value))

    def getBwdPacketLenMax(self):
        return self.bwd_packet_len_max

    def setBwdPacketLenMax(self, value):
        self.bwd_packet_len_max = value

    def getBwdPacketLenMin(self):
        return self.bwd_packet_len_min

    def setBwdPacketLenMin(self, value):
        self.bwd_packet_len_min = value

    def getBwdPacketLenMean(self):
        return self.bwd_packet_len_mean

    def setBwdPacketLenMean(self, value):
        self.bwd_packet_len_mean = value

    def getBwdPacketLenStd(self):
        return self.bwd_packet_len_std

    def setBwdPacketLenStd(self, value):
        self.bwd_packet_len_std = value

    def getFlowIATMean(self):
        return self.flow_IAT_mean

    def setFlowIATMean(self, value):
        self.flow_IAT_mean = int(round(value))

    def getFlowIATStd(self):
        return self.flow_IAT_std

    def setFlowIATStd(self, value):
        self.flow_IAT_std = value

    def getFlowIATMax(self):
        return self.flow_IAT_max

    def setFlowIATMax(self, value):
        self.flow_IAT_max = int(round(value))

    def getFlowIATMin(self):
        return self.flow_IAT_min

    def setFlowIATMin(self, value):
        self.flow_IAT_min = int(round(value))

    def getFwdIATTotal(self):
        return self.fwd_IAT_total

    def setFwdIATTotal(self, value):
        self.fwd_IAT_total = int(round(value))

    def getFwdIATMean(self):
        return self.fwd_IAT_mean

    def setFwdIATMean(self, value):
        self.fwd_IAT_mean = value

    def getFwdIATStd(self):
        return self.fwd_IAT_std

    def setFwdIATStd(self, value):
        self.fwd_IAT_std = value

    def getFwdIATMax(self):
        return self.fwd_IAT_max

    def setFwdIATMax(self, value):
        self.fwd_IAT_max = int(round(value))

    def getFwdIATMin(self):
        return self.fwd_IAT_min

    def setFwdIATMin(self, value):
        self.fwd_IAT_min = int(round(value))

    def getBwdIATTotal(self):
        return self.bwd_IAT_total

    def setBwdIATTotal(self, value):
        self.bwd_IAT_total = int(round(value))

    def getBwdIATMean(self):
        return self.bwd_IAT_mean

    def setBwdIATMean(self, value):
        self.bwd_IAT_mean = value

    def getBwdIATStd(self):
        return self.bwd_IAT_std

    def setBwdIATStd(self, value):
        self.bwd_IAT_std = value

    def getBwdIATMax(self):
        return self.bwd_IAT_max

    def setBwdIATMax(self, value):
        self.bwd_IAT_max = int(round(value))

    def getBwdIATMin(self):
        return self.bwd_IAT_min

    def setBwdIATMin(self, value):
        self.bwd_IAT_min = int(round(value))

    def getFwdPSHFlags(self):
        return self.fwd_PSH_flags

    def setFwdPSHFlags(self, value):
        self.fwd_PSH_flags = value

    def getFwdPackets_s(self):
        return self.fwd_packets_s

    def setFwdPackets_s(self, value):
        self.fwd_packets_s = value

    def getMaxPacketLen(self):
        return self.max_packet_len

    def setMaxPacketLen(self, value):
        self.max_packet_len = value

    def getPacketLenMean(self):
        return self.packet_len_mean

    def setPacketLenMean(self, value):
        self.packet_len_mean = value

    def getPacketLenStd(self):
        return self.packet_len_std

    def setPacketLenStd(self, value):
        self.packet_len_std = value

    def getPacketLenVar(self):
        return self.packet_len_var

    def setPacketLenVar(self, value):
        self.packet_len_var = value

    def getFINFlagCount(self):
        return self.FIN_flag_count

    def setFINFlagCount(self, value):
        self.FIN_flag_count = value

    def getSYNFlagCount(self):
        return self.SYN_flag_count

    def setSYNFlagCount(self, value):
        self.SYN_flag_count = value

    def getPSHFlagCount(self):
        return self.PSH_flag_count

    def setPSHFlagCount(self, value):
        self.PSH_flag_count = value

    def getACKFlagCount(self):
        return self.ACK_flag_count

    def setACKFlagCount(self, value):
        self.ACK_flag_count = value

    def getURGFlagCount(self):
        return self.URG_flag_count

    def setURGFlagCount(self, value):
        self.URG_flag_count = value

    def getAvgPacketSize(self):
        return self.avg_packet_size

    def setAvgPacketSize(self, value):
        self.avg_packet_size = value

    def getAvgBwdSegmentSize(self):
        return self.avg_bwd_segment_size

    def setAvgBwdSegmentSize(self, value):
        self.avg_bwd_segment_size = value

    def getInitWinBytesFwd(self):
        return self.init_win_bytes_forward

    def setInitBytesFwd(self, value):
        self.init_win_bytes_forward = value

    def getInitWinBytesBwd(self):
        return self.init_win_bytes_backward

    def setInitWinBytesBwd(self, value):
        self.init_win_bytes_backward = value

    def getActiveMin(self):
        return self.active_min

    def setActiveMin(self, value):
        self.active_min = value

    def getIdleMean(self):
        return self.idle_mean

    def setIdleMean(self, value):
        self.idle_mean = value

    def getIdleStd(self):
        return self.idle_std

    def setIdleStd(self, value):
        self.idle_std = value

    def getIdleMax(self):
        return self.idle_max

    def setIdleMax(self, value):
        self.idle_max = value

    def getIdleMin(self):
        return self.idle_min

    def setIdleMin(self, value):
        self.idle_min = value

    def getSrcIP(self):
        return self.idle_min

    def setIdleMin(self, value):
        self.idle_min = value



    def getSrc(self):
        return self.src

    def getDest(self):
        return self.dest

    def getSrcPort(self):
        return self.src_port

    def getProtocol(self):
        return self.protocol


    def setSrc(self, value):
        self.src = value

    def setDest(self, value):
        self.dest = value

    def setSrcPort(self, value):
        self.src_port = value

    def setProtocol(self, value):
        self.protocol = value

    def setPID(self, value):
        self.pid = value

    def setPName(self, value):
        self.p_name = value

    def getPID(self):
        return self.pid

    def getPName(self):
        return self.p_name

