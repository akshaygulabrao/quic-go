package congestion

import (
	"math"
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

// This cubic implementation is based on the one found in Chromiums's QUIC
// implementation, in the files net/quic/congestion_control/cubic.{hh,cc}.

// Constants based on TCP defaults.
// The following constants are in 2^10 fractions of a second instead of ms to
// allow a 10 shift right to divide.

// 1024*1024^3 (first 1024 is from 0.100^3)
// where 0.100 is 100 ms which is the scaling
// round trip time.
const vivacecubeScale = 40
const vivacecubeCongestionWindowScale = 410
const vivacecubeFactor protocol.PacketNumber = 1 << cubeScale / cubeCongestionWindowScale

const vivacedefaultNumConnections = 2

// Default Cubic backoff factor
const vivacebeta float32 = 0.7

// Additional backoff factor when loss occurs in the concave part of the Cubic
// curve. This additional backoff factor is expected to give up bandwidth to
// new concurrent flows and speed up convergence.
const vivacebetaLastMax float32 = 0.85

// If true, Cubic's epoch is shifted when the sender is application-limited.
const vivaceshiftQuicCubicEpochWhenAppLimited = true

const vivacemaxCubicTimeInterval = 30 * time.Millisecond

// Cubic implements the cubic algorithm from TCP
type Vivace struct {
	clock Clock
	// Number of connections to simulate.
	numConnections int
	// Time when this cycle started, after last loss event.
	epoch time.Time
	// Time when sender went into application-limited period. Zero if not in
	// application-limited period.
	appLimitedStartTime time.Time
	// Time when we updated last_congestion_window.
	lastUpdateTime time.Time
	// Last congestion window (in packets) used.
	lastCongestionWindow protocol.PacketNumber
	// Max congestion window (in packets) used just before last loss event.
	// Note: to improve fairness to other streams an additional back off is
	// applied to this value if the new value is below our latest value.
	lastMaxCongestionWindow protocol.PacketNumber
	// Number of acked packets since the cycle started (epoch).
	ackedPacketsCount protocol.PacketNumber
	// TCP Reno equivalent congestion window in packets.
	estimatedTCPcongestionWindow protocol.PacketNumber
	// Origin point of cubic function.
	originPointCongestionWindow protocol.PacketNumber
	// Time to origin point of cubic function in 2^10 fractions of a second.
	timeToOriginPoint uint32
	// Last congestion window in packets computed by cubic function.
	lastTargetCongestionWindow protocol.PacketNumber
}

// NewCubic returns a new Cubic instance
func NewVivace(clock Clock) *Vivace {
	v := &Vivace{
		clock:          clock,
		numConnections: defaultNumConnections,
	}
	v.Reset()
	return v
}

// Reset is called after a timeout to reset the cubic state
func (v *Vivace) Reset() {
	v.epoch = time.Time{}
	v.appLimitedStartTime = time.Time{}
	v.lastUpdateTime = time.Time{}
	v.lastCongestionWindow = 0
	v.lastMaxCongestionWindow = 0
	v.ackedPacketsCount = 0
	v.estimatedTCPcongestionWindow = 0
	v.originPointCongestionWindow = 0
	v.timeToOriginPoint = 0
	v.lastTargetCongestionWindow = 0
}

func (v *Vivace) alpha() float32 {
	// TCPFriendly alpha is described in Section 3.3 of the CUBIC paper. Note that
	// beta here is a cwnd multiplier, and is equal to 1-beta from the paper.
	// We derive the equivalent alpha for an N-connection emulation as:
	b := v.beta()
	return 3 * float32(v.numConnections) * float32(v.numConnections) * (1 - b) / (1 + b)
}

func (v *Vivace) beta() float32 {
	// kNConnectionBeta is the backoff factor after loss for our N-connection
	// emulation, which emulates the effective backoff of an ensemble of N
	// TCP-Reno connections on a single loss event. The effective multiplier is
	// computed as:
	return (float32(v.numConnections) - 1 + beta) / float32(v.numConnections)
}

// OnApplicationLimited is called on ack arrival when sender is unable to use
// the available congestion window. Resets Cubic state during quiescence.
func (v *Vivace) OnApplicationLimited() {
	if shiftQuicCubicEpochWhenAppLimited {
		// When sender is not using the available congestion window, Cubic's epoch
		// should not continue growing. Record the time when sender goes into an
		// app-limited period here, to compensate later when cwnd growth happens.
		if v.appLimitedStartTime.IsZero() {
			v.appLimitedStartTime = v.clock.Now()
		}
	} else {
		// When sender is not using the available congestion window, Cubic's epoch
		// should not continue growing. Reset the epoch when in such a period.
		v.epoch = time.Time{}
	}
}

// CongestionWindowAfterPacketLoss computes a new congestion window to use after
// a loss event. Returns the new congestion window in packets. The new
// congestion window is a multiplicative decrease of our current window.
func (v *Vivace) CongestionWindowAfterPacketLoss(currentCongestionWindow protocol.PacketNumber) protocol.PacketNumber {
	if currentCongestionWindow < v.lastMaxCongestionWindow {
		// We never reached the old max, so assume we are competing with another
		// flow. Use our extra back off factor to allow the other flow to go up.
		v.lastMaxCongestionWindow = protocol.PacketNumber(betaLastMax * float32(currentCongestionWindow))
	} else {
		v.lastMaxCongestionWindow = currentCongestionWindow
	}
	v.epoch = time.Time{} // Reset time.
	return protocol.PacketNumber(float32(currentCongestionWindow) * v.beta())
}

// CongestionWindowAfterAck computes a new congestion window to use after a received ACK.
// Returns the new congestion window in packets. The new congestion window
// follows a cubic function that depends on the time passed since last
// packet loss.
func (v *Vivace) CongestionWindowAfterAck(currentCongestionWindow protocol.PacketNumber, delayMin time.Duration) protocol.PacketNumber {
	v.ackedPacketsCount++ // Packets acked.
	currentTime := v.clock.Now()

	// Cubic is "independent" of RTT, the update is limited by the time elapsed.
	if v.lastCongestionWindow == currentCongestionWindow && (currentTime.Sub(v.lastUpdateTime) <= maxCubicTimeInterval) {
		return utils.MaxPacketNumber(v.lastTargetCongestionWindow, v.estimatedTCPcongestionWindow)
	}
	v.lastCongestionWindow = currentCongestionWindow
	v.lastUpdateTime = currentTime

	if v.epoch.IsZero() {
		// First ACK after a loss event.
		v.epoch = currentTime   // Start of epoch.
		v.ackedPacketsCount = 1 // Reset count.
		// Reset estimated_tcp_congestion_window_ to be in sync with cubic.
		v.estimatedTCPcongestionWindow = currentCongestionWindow
		if v.lastMaxCongestionWindow <= currentCongestionWindow {
			v.timeToOriginPoint = 0
			v.originPointCongestionWindow = currentCongestionWindow
		} else {
			v.timeToOriginPoint = uint32(math.Cbrt(float64(cubeFactor * (v.lastMaxCongestionWindow - currentCongestionWindow))))
			v.originPointCongestionWindow = v.lastMaxCongestionWindow
		}
	} else {
		// If sender was app-limited, then freeze congestion window growth during
		// app-limited period. Continue growth now by shifting the epoch-start
		// through the app-limited period.
		if shiftQuicCubicEpochWhenAppLimited && !v.appLimitedStartTime.IsZero() {
			shift := currentTime.Sub(v.appLimitedStartTime)
			v.epoch = v.epoch.Add(shift)
			v.appLimitedStartTime = time.Time{}
		}
	}

	// Change the time unit from microseconds to 2^10 fractions per second. Take
	// the round trip time in account. This is done to allow us to use shift as a
	// divide operator.
	elapsedTime := int64((currentTime.Add(delayMin).Sub(v.epoch)/time.Microsecond)<<10) / 1000000

	offset := int64(v.timeToOriginPoint) - elapsedTime
	// Right-shifts of negative, signed numbers have
	// implementation-dependent behavior.  Force the offset to be
	// positive, similar to the kernel implementation.
	if offset < 0 {
		offset = -offset
	}
	deltaCongestionWindow := protocol.PacketNumber((cubeCongestionWindowScale * offset * offset * offset) >> cubeScale)
	var targetCongestionWindow protocol.PacketNumber
	if elapsedTime > int64(v.timeToOriginPoint) {
		targetCongestionWindow = v.originPointCongestionWindow + deltaCongestionWindow
	} else {
		targetCongestionWindow = v.originPointCongestionWindow - deltaCongestionWindow
	}
	// With dynamic beta/alpha based on number of active streams, it is possible
	// for the required_ack_count to become much lower than acked_packets_count_
	// suddenly, leading to more than one iteration through the following loop.
	for {
		// Update estimated TCP congestion_window.
		requiredAckCount := protocol.PacketNumber(float32(v.estimatedTCPcongestionWindow) / v.alpha())
		if v.ackedPacketsCount < requiredAckCount {
			break
		}
		v.ackedPacketsCount -= requiredAckCount
		v.estimatedTCPcongestionWindow++
	}

	// We have a new cubic congestion window.
	v.lastTargetCongestionWindow = targetCongestionWindow

	// Compute target congestion_window based on cubic target and estimated TCP
	// congestion_window, use highest (fastest).
	if targetCongestionWindow < v.estimatedTCPcongestionWindow {
		targetCongestionWindow = v.estimatedTCPcongestionWindow
	}

	return targetCongestionWindow
}

// SetNumConnections sets the number of emulated connections
func (v *Vivace) SetNumConnections(n int) {
	v.numConnections = n
}