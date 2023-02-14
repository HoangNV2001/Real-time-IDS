import statistics

from flow.FlowFeature import FlowFeatures

from datetime import datetime
threshold = 5


class Flow:
    def __init__(self, packet):
        self.packetInfos = [packet]
        self.fwdPacketInfos = [packet]
        self.bwdPacketInfos = []

        self.flowFeatures = FlowFeatures()
        self.flowFeatures.setDestPort(packet.getDestPort())

        self.flowFeatures.setPID(packet.getPID())
        self.flowFeatures.setPName(packet.getPName())



        self.flowFeatures.setFwdPSHFlags(0 if not packet.getURGFlag() else 1)
        self.flowFeatures.setMaxPacketLen(packet.getPayloadBytes())
        self.flowFeatures.setPacketLenMean(packet.getPayloadBytes())
        self.flowFeatures.setFINFlagCount(1 if packet.getFINFlag() else 0)
        self.flowFeatures.setSYNFlagCount(1 if packet.getSYNFlag() else 0)
        self.flowFeatures.setPSHFlagCount(1 if packet.getPSHFlag() else 0)
        self.flowFeatures.setACKFlagCount(1 if packet.getACKFlag() else 0)
        self.flowFeatures.setURGFlagCount(1 if packet.getURGFlag() else 0)

        self.flowFeatures.setAvgPacketSize(packet.getPacketSize())
        self.flowFeatures.setInitBytesFwd(packet.getWinBytes())

        self.flowFeatures.setSrc(packet.getSrc())
        self.flowFeatures.setDest(packet.getDest())
        self.flowFeatures.setSrcPort(packet.getSrcPort())
        self.flowFeatures.setProtocol(packet.getProtocol())


        self.flowLastSeen = packet.getTimestamp()
        self.fwdLastSeen = packet.getTimestamp()
        self.bwdLastSeen = 0
        self.flowStartTime = packet.getTimestamp()
        self.startActiveTime = packet.getTimestamp()
        self.endActiveTime = packet.getTimestamp()

        self.flowIAT = []
        self.fwdIAT = []
        self.bwdIAT = []
        self.flowActive = []
        self.flowIdle = []

        self.packet_count = 1
        self.fwd_packet_count = 1
        self.bwd_packet_count = 0

    def getFlowLastSeen(self):
        return self.flowLastSeen

    def getFlowStartTime(self):
        return self.flowStartTime

    def new(self, packetInfo, direction):
        if direction == 'bwd':
            self.bwdPacketInfos.append(packetInfo)

            if self.bwd_packet_count == 0:
                # first backward packet, do some initalising
                self.flowFeatures.setBwdPacketLenMax(packetInfo.getPayloadBytes())
                self.flowFeatures.setBwdPacketLenMin(packetInfo.getPayloadBytes())
                self.flowFeatures.setInitWinBytesBwd(packetInfo.getWinBytes())
            else:
                self.flowFeatures.setBwdPacketLenMax(
                    max(self.flowFeatures.bwd_packet_len_max, packetInfo.getPayloadBytes()))
                self.flowFeatures.setBwdPacketLenMin(
                    min(self.flowFeatures.bwd_packet_len_min, packetInfo.getPayloadBytes()))
                self.bwdIAT.append((packetInfo.getTimestamp() - self.bwdLastSeen) * 1000 * 1000)

            self.bwd_packet_count = self.bwd_packet_count + 1
            self.bwdLastSeen = packetInfo.getTimestamp()

        else:
            self.fwdPacketInfos.append(packetInfo)
            self.fwdIAT.append((packetInfo.getTimestamp() - self.fwdLastSeen) * 1000 * 1000)
            self.flowFeatures.setFwdPSHFlags(max(1 if packetInfo.getURGFlag() else 0,
                                                 self.flowFeatures.getFwdPSHFlags()))
            self.fwd_packet_count = self.fwd_packet_count + 1
            self.fwdLastSeen = packetInfo.getTimestamp()

        self.flowFeatures.setMaxPacketLen(max(self.flowFeatures.getMaxPacketLen(), packetInfo.getPayloadBytes()))

        if packetInfo.getFINFlag():
            self.flowFeatures.setFINFlagCount(1)
        if packetInfo.getSYNFlag():
            self.flowFeatures.setSYNFlagCount(1)
        if packetInfo.getPSHFlag():
            self.flowFeatures.setPSHFlagCount(1)
        if packetInfo.getACKFlag():
            self.flowFeatures.setACKFlagCount(1)
        if packetInfo.getURGFlag():
            self.flowFeatures.setURGFlagCount(1)

        time = packetInfo.getTimestamp()
        if time - self.endActiveTime > threshold:
            if self.endActiveTime - self.startActiveTime > 0:
                self.flowActive.append(self.endActiveTime - self.startActiveTime)
            self.flowIdle.append(time - self.endActiveTime)
            self.startActiveTime = time
            self.endActiveTime = time
        else:
            self.endActiveTime = time

        self.packet_count = self.packet_count + 1
        self.packetInfos.append(packetInfo)
        self.flowIAT.append((packetInfo.getTimestamp() - self.flowLastSeen) * 1000 * 1000)
        self.flowLastSeen = packetInfo.getTimestamp()

    def terminated(self):
        duration = (self.flowLastSeen - self.flowStartTime) * 1000 * 1000
        self.flowFeatures.setFlowDuration(duration)

        bwd_packet_lens = [x.getPayloadBytes() for x in self.bwdPacketInfos]
        if len(bwd_packet_lens) > 0:
            self.flowFeatures.setBwdPacketLenMean(statistics.mean(bwd_packet_lens))
            if len(bwd_packet_lens) > 1:
                self.flowFeatures.setBwdPacketLenStd(statistics.stdev(bwd_packet_lens))

        if len(self.flowIAT) > 0:
            self.flowFeatures.setFlowIATMean(statistics.mean(self.flowIAT))
            self.flowFeatures.setFlowIATMax(max(self.flowIAT))
            self.flowFeatures.setFlowIATMin(min(self.flowIAT))
            if len(self.flowIAT) > 1:
                self.flowFeatures.setFlowIATStd(statistics.stdev(self.flowIAT))

        if len(self.fwdIAT) > 0:
            self.flowFeatures.setFwdIATTotal(sum(self.fwdIAT))
            self.flowFeatures.setFwdIATMean(statistics.mean(self.fwdIAT))
            self.flowFeatures.setFwdIATMax(max(self.fwdIAT))
            self.flowFeatures.setFwdIATMin(min(self.fwdIAT))
            if len(self.fwdIAT) > 1:
                self.flowFeatures.setFwdIATStd(statistics.stdev(self.fwdIAT))

        if len(self.bwdIAT) > 0:
            self.flowFeatures.setBwdIATTotal(sum(self.bwdIAT))
            self.flowFeatures.setBwdIATMean(statistics.mean(self.bwdIAT))
            self.flowFeatures.setBwdIATMax(max(self.bwdIAT))
            self.flowFeatures.setBwdIATMin(min(self.bwdIAT))
            if len(self.bwdIAT) > 1:
                self.flowFeatures.setBwdIATStd(statistics.stdev(self.bwdIAT))

        self.flowFeatures.setFwdPackets_s(0 if duration == 0 else self.fwd_packet_count / (duration / (1000 * 1000)))

        packet_lens = [x.getPayloadBytes() for x in self.packetInfos]
        if len(packet_lens) > 0:
            self.flowFeatures.setPacketLenMean(statistics.mean(packet_lens))
            if len(packet_lens) > 1:
                self.flowFeatures.setPacketLenStd(statistics.stdev(packet_lens))
                self.flowFeatures.setPacketLenVar(statistics.variance(packet_lens))

        packet_sizes =[x.getPacketSize() for x in self.packetInfos]
        self.flowFeatures.setAvgPacketSize(sum(packet_sizes) / self.packet_count)

        if self.bwd_packet_count != 0:
            self.flowFeatures.setAvgBwdSegmentSize(sum(bwd_packet_lens) / self.bwd_packet_count)

        if len(self.flowActive) > 0:
            self.flowFeatures.setActiveMin(min(self.flowActive))

        if len(self.flowIdle) > 0:
            self.flowFeatures.setIdleMean(statistics.mean(self.flowIdle))
            self.flowFeatures.setIdleMax(max(self.flowIdle))
            self.flowFeatures.setIdleMin(min(self.flowIdle))
            if len(self.flowIdle) > 1:
                self.flowFeatures.setIdleStd(statistics.stdev(self.flowIdle))

        return [
                self.flowFeatures.getFlowDuration(),
                self.flowFeatures.getBwdPacketLenMax(),
                self.flowFeatures.getBwdPacketLenMin(),
                self.flowFeatures.getBwdPacketLenMean(),
                self.flowFeatures.getBwdPacketLenStd(),
                self.flowFeatures.getFlowIATMean(),
                self.flowFeatures.getFlowIATStd(),
                self.flowFeatures.getFlowIATMax(),
                self.flowFeatures.getFlowIATMin(),
                self.flowFeatures.getFwdIATTotal(),
                self.flowFeatures.getFwdIATMean(),
                self.flowFeatures.getFwdIATStd(),
                self.flowFeatures.getFwdIATMax(),
                self.flowFeatures.getFwdIATMin(),
                self.flowFeatures.getBwdIATTotal(),
                self.flowFeatures.getBwdIATMean(),
                self.flowFeatures.getBwdIATStd(),
                self.flowFeatures.getBwdIATMax(),
                self.flowFeatures.getBwdIATMin(),
                self.flowFeatures.getFwdPSHFlags(),
                self.flowFeatures.getFwdPackets_s(),
                self.flowFeatures.getMaxPacketLen(),
                self.flowFeatures.getPacketLenMean(),
                self.flowFeatures.getPacketLenStd(),
                self.flowFeatures.getPacketLenVar(),
                self.flowFeatures.getFINFlagCount(),
                self.flowFeatures.getSYNFlagCount(),
                self.flowFeatures.getPSHFlagCount(),
                self.flowFeatures.getACKFlagCount(),
                self.flowFeatures.getURGFlagCount(),
                self.flowFeatures.getAvgPacketSize(),
                self.flowFeatures.getAvgBwdSegmentSize(),
                self.flowFeatures.getInitWinBytesFwd(),
                self.flowFeatures.getInitWinBytesBwd(),
                self.flowFeatures.getActiveMin(),
                self.flowFeatures.getIdleMean(),
                self.flowFeatures.getIdleStd(),
                self.flowFeatures.getIdleMax(),
                self.flowFeatures.getIdleMin(),

                
                self.flowFeatures.getSrc(),
                self.flowFeatures.getSrcPort(),
                self.flowFeatures.getDest(),
                self.flowFeatures.getDestPort(),
                self.flowFeatures.getProtocol(),
                datetime.fromtimestamp(self.getFlowStartTime()),
                datetime.fromtimestamp(self.getFlowLastSeen()),
                
                self.flowFeatures.getPName(),
                self.flowFeatures.getPID(),
                ]
