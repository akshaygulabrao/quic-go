package congestion

import (
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)



type VivaceSender struct {
	hybridSlowStart HybridSlowStart
	prr             PrrSender
	rttStats        *RTTStats
	stats           connectionStats
	vivace           *Vivace
	vivaceSenders     map[protocol.PathID]*VivaceSender

	reno bool

	// Track the largest packet that has been sent.
	largestSentPacketNumber protocol.PacketNumber

	// Track the largest packet that has been acked.
	largestAckedPacketNumber protocol.PacketNumber

	// Track the largest packet number outstanding when a CWND cutback occurs.
	largestSentAtLastCutback protocol.PacketNumber

	// Congestion window in packets.
	congestionWindow protocol.PacketNumber

	// Slow start congestion window in packets, aka ssthresh.
	slowstartThreshold protocol.PacketNumber

	// Whether the last loss event caused us to exit slowstart.
	// Used for stats collection of slowstartPacketsLost
	lastCutbackExitedSlowstart bool

	// When true, exit slow start with large cutback of congestion window.
	slowStartLargeReduction bool

	// Minimum congestion window in packets.
	minCongestionWindow protocol.PacketNumber

	// Maximum number of outstanding packets for tcp.
	maxTCPCongestionWindow protocol.PacketNumber

	// Number of connections to simulate.
	numConnections int

	// ACK counter for the Reno implementation.
	congestionWindowCount protocol.ByteCount

	initialCongestionWindow    protocol.PacketNumber
	initialMaxCongestionWindow protocol.PacketNumber
}

// NewCubicSender makes a new cubic sender
//func NewCubicSender(clock Clock, rttStats *RTTStats, reno bool, initialCongestionWindow, initialMaxCongestionWindow protocol.PacketNumber) SendAlgorithmWithDebugInfo {
	//return &CubicSender{
		//rttStats:                   rttStats,
		//initialCongestionWindow:    initialCongestionWindow,
		//initialMaxCongestionWindow: initialMaxCongestionWindow,
		//congestionWindow:           initialCongestionWindow,
		//minCongestionWindow:        defaultMinimumCongestionWindow,
		//slowstartThreshold:         initialMaxCongestionWindow,
		//maxTCPCongestionWindow:     initialMaxCongestionWindow,
		//numConnections:             defaultNumConnections,
		//cubic:                      NewCubic(clock),
		//reno:                       reno,
	//}
//}

func NewVivaceSender(vivaceSenders map[protocol.PathID]*VivaceSender,clock Clock, rttStats *RTTStats, reno bool, initialCongestionWindow, initialMaxCongestionWindow protocol.PacketNumber) SendAlgorithmWithDebugInfo {
	return &VivaceSender{
	
	rttStats:                   rttStats,
	initialCongestionWindow:    initialCongestionWindow,
	initialMaxCongestionWindow: initialMaxCongestionWindow,
	congestionWindow:           initialCongestionWindow,
	minCongestionWindow:        defaultMinimumCongestionWindow,
	slowstartThreshold:         initialMaxCongestionWindow,
	maxTCPCongestionWindow:     initialMaxCongestionWindow,
	numConnections:             defaultNumConnections,
	vivace:                     NewVivace(clock),
	reno:                       reno,
	vivaceSenders:              vivaceSenders,

	}
}

func (v *VivaceSender) TimeUntilSend(now time.Time, bytesInFlight protocol.ByteCount) time.Duration {
	return 0
}

func (v *VivaceSender) OnPacketSent(sentTime time.Time, bytesInFlight protocol.ByteCount, packetNumber protocol.PacketNumber, bytes protocol.ByteCount, isRetransmittable bool) bool {
	// Only update bytesInFlight for data packets.
	if !isRetransmittable {
		return false
	}
	if v.InRecovery() {
		// PRR is used when in recovery.
		v.prr.OnPacketSent(bytes)
	}
	v.largestSentPacketNumber = packetNumber
	v.hybridSlowStart.OnPacketSent(packetNumber)
	return true
}

func (v *VivaceSender) InRecovery() bool {
	return v.largestAckedPacketNumber <= v.largestSentAtLastCutback && v.largestAckedPacketNumber != 0
}

func (v *VivaceSender) InSlowStart() bool {
	return v.GetCongestionWindow() < v.GetSlowStartThreshold()
}

func (v *VivaceSender) GetCongestionWindow() protocol.ByteCount {
	return protocol.ByteCount(v.congestionWindow) * protocol.DefaultTCPMSS
}

func (v *VivaceSender) GetSlowStartThreshold() protocol.ByteCount {
	return protocol.ByteCount(v.slowstartThreshold) * protocol.DefaultTCPMSS
}

func (v *VivaceSender) ExitSlowstart() {
	v.slowstartThreshold = v.congestionWindow
}

func (v *VivaceSender) SlowstartThreshold() protocol.PacketNumber {
	return v.slowstartThreshold
}

func (v *VivaceSender) MaybeExitSlowStart() {
	if v.InSlowStart() && v.hybridSlowStart.ShouldExitSlowStart(v.rttStats.LatestRTT(), v.rttStats.MinRTT(), v.GetCongestionWindow()/protocol.DefaultTCPMSS) {
		v.ExitSlowstart()
	}
}

func (v *VivaceSender) OnPacketAcked(ackedPacketNumber protocol.PacketNumber, ackedBytes protocol.ByteCount, bytesInFlight protocol.ByteCount) {
	v.largestAckedPacketNumber = utils.MaxPacketNumber(ackedPacketNumber, v.largestAckedPacketNumber)
	if v.InRecovery() {
		// PRR is used when in recovery.
		v.prr.OnPacketAcked(ackedBytes)
		return
	}
	v.maybeIncreaseCwnd(ackedPacketNumber, ackedBytes, bytesInFlight)
	if v.InSlowStart() {
		v.hybridSlowStart.OnPacketAcked(ackedPacketNumber)
	}
}

func (v *VivaceSender) OnPacketLost(packetNumber protocol.PacketNumber, lostBytes protocol.ByteCount, bytesInFlight protocol.ByteCount) {
	// TCP NewReno (RFC6582) says that once a loss occurs, any losses in packets
	// already sent should be treated as a single loss event, since it's expected.
	if packetNumber <= v.largestSentAtLastCutback {
		if v.lastCutbackExitedSlowstart {
			v.stats.slowstartPacketsLost++
			v.stats.slowstartBytesLost += lostBytes
			if v.slowStartLargeReduction {
				if v.stats.slowstartPacketsLost == 1 || (v.stats.slowstartBytesLost/protocol.DefaultTCPMSS) > (v.stats.slowstartBytesLost-lostBytes)/protocol.DefaultTCPMSS {
					// Reduce congestion window by 1 for every mss of bytes lost.
					v.congestionWindow = utils.MaxPacketNumber(v.congestionWindow-1, v.minCongestionWindow)
				}
				v.slowstartThreshold = v.congestionWindow
			}
		}
		return
	}
	v.lastCutbackExitedSlowstart = v.InSlowStart()
	if v.InSlowStart() {
		v.stats.slowstartPacketsLost++
	}

	v.prr.OnPacketLost(bytesInFlight)

	// TODO(chromium): Separate out all of slow start into a separate class.
	if v.slowStartLargeReduction && v.InSlowStart() {
		v.congestionWindow = v.congestionWindow - 1
	} else if v.reno {
		v.congestionWindow = protocol.PacketNumber(float32(v.congestionWindow) * v.RenoBeta())
	} else {
		v.congestionWindow = v.vivace.CongestionWindowAfterPacketLoss(v.congestionWindow)
	}
	// Enforce a minimum congestion window.
	if v.congestionWindow < v.minCongestionWindow {
		v.congestionWindow = v.minCongestionWindow
	}
	v.slowstartThreshold = v.congestionWindow
	v.largestSentAtLastCutback = v.largestSentPacketNumber
	// reset packet count from congestion avoidance mode. We start
	// counting again when we're out of recovery.
	v.congestionWindowCount = 0
}

func (v *VivaceSender) RenoBeta() float32 {
	// kNConnectionBeta is the backoff factor after loss for our N-connection
	// emulation, which emulates the effective backoff of an ensemble of N
	// TCP-Reno connections on a single loss event. The effective multiplier is
	// computed as:
	return (float32(v.numConnections) - 1. + renoBeta) / float32(v.numConnections)
}

// Called when we receive an ack. Normal TCP tracks how many packets one ack
// represents, but quic has a separate ack for each packet.
func (v *VivaceSender) maybeIncreaseCwnd(ackedPacketNumber protocol.PacketNumber, ackedBytes protocol.ByteCount, bytesInFlight protocol.ByteCount) {
	// Do not increase the congestion window unless the sender is close to using
	// the current window.
	if !v.isCwndLimited(bytesInFlight) {
		v.vivace.OnApplicationLimited()
		return
	}
	if v.congestionWindow >= v.maxTCPCongestionWindow {
		return
	}
	if v.InSlowStart() {
		// TCP slow start, exponential growth, increase by one for each ACK.
		v.congestionWindow++
		return
	}
	if v.reno {
		// Classic Reno congestion avoidance.
		v.congestionWindowCount++
		// Divide by num_connections to smoothly increase the CWND at a faster
		// rate than conventional Reno.
		if protocol.PacketNumber(v.congestionWindowCount*protocol.ByteCount(v.numConnections)) >= v.congestionWindow {
			v.congestionWindow++
			v.congestionWindowCount = 0
		}
	} else {
		v.congestionWindow = utils.MinPacketNumber(v.maxTCPCongestionWindow, v.vivace.CongestionWindowAfterAck(v.congestionWindow, v.rttStats.MinRTT()))
	}
}

func (v *VivaceSender) isCwndLimited(bytesInFlight protocol.ByteCount) bool {
	congestionWindow := v.GetCongestionWindow()
	if bytesInFlight >= congestionWindow {
		return true
	}
	availableBytes := congestionWindow - bytesInFlight
	slowStartLimited := v.InSlowStart() && bytesInFlight > congestionWindow/2
	return slowStartLimited || availableBytes <= maxBurstBytes
}

// BandwidthEstimate returns the current bandwidth estimate
func (v *VivaceSender) BandwidthEstimate() Bandwidth {
	srtt := v.rttStats.SmoothedRTT()
	if srtt == 0 {
		// If we haven't measured an rtt, the bandwidth estimate is unknown.
		return 0
	}
	return BandwidthFromDelta(v.GetCongestionWindow(), srtt)
}

// HybridSlowStart returns the hybrid slow start instance for testing
func (v *VivaceSender) HybridSlowStart() *HybridSlowStart {
	return &v.hybridSlowStart
}

// SetNumEmulatedConnections sets the number of emulated connections
func (v *VivaceSender) SetNumEmulatedConnections(n int) {
	v.numConnections = utils.Max(n, 1)
	v.vivace.SetNumConnections(v.numConnections)
}

// OnRetransmissionTimeout is called on an retransmission timeout
func (v *VivaceSender) OnRetransmissionTimeout(packetsRetransmitted bool) {
	v.largestSentAtLastCutback = 0
	if !packetsRetransmitted {
		return
	}
	v.hybridSlowStart.Restart()
	v.vivace.Reset()
	v.slowstartThreshold = v.congestionWindow / 2
	v.congestionWindow = v.minCongestionWindow
}

// OnConnectionMigration is called when the connection is migrated (?)
func (v *VivaceSender) OnConnectionMigration() {
	v.hybridSlowStart.Restart()
	v.prr = PrrSender{}
	v.largestSentPacketNumber = 0
	v.largestAckedPacketNumber = 0
	v.largestSentAtLastCutback = 0
	v.lastCutbackExitedSlowstart = false
	v.vivace.Reset()
	v.congestionWindowCount = 0
	v.congestionWindow = v.initialCongestionWindow
	v.slowstartThreshold = v.initialMaxCongestionWindow
	v.maxTCPCongestionWindow = v.initialMaxCongestionWindow
}

// SetSlowStartLargeReduction allows enabling the SSLR experiment
func (v *VivaceSender) SetSlowStartLargeReduction(enabled bool) {
	v.slowStartLargeReduction = enabled
}

// RetransmissionDelay gives the time to retransmission
func (v *VivaceSender) RetransmissionDelay() time.Duration {
	if v.rttStats.SmoothedRTT() == 0 {
		return 0
	}
	return v.rttStats.SmoothedRTT() + v.rttStats.MeanDeviation()*4
}

func (v *VivaceSender) SmoothedRTT() time.Duration {
	return v.rttStats.SmoothedRTT()
}
