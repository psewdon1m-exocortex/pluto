package syncstate

import "sync/atomic"

var captureSourceReads, captureSourceBytes, capturePrivateReads, capturePrivateBytes atomic.Int64
var captureTransportReads, captureTransportBytes atomic.Int64
var stateTransactions, stateCommits, stateRollbacks atomic.Int64

type CaptureMetrics struct {
	SourceReads              int64 `json:"source_reads"`
	SourceHashBytes          int64 `json:"source_hash_bytes"`
	PrivateVerificationReads int64 `json:"private_verification_reads"`
	PrivateVerificationBytes int64 `json:"private_verification_bytes"`
	TransportHashReads       int64 `json:"transport_hash_reads"`
	TransportHashBytes       int64 `json:"transport_hash_bytes"`
	Transactions             int64 `json:"transactions"`
	CommittedTransactions    int64 `json:"committed_transactions"`
	RolledBackTransactions   int64 `json:"rolled_back_transactions"`
}

func CaptureMetricSnapshot() CaptureMetrics {
	return CaptureMetrics{captureSourceReads.Load(), captureSourceBytes.Load(), capturePrivateReads.Load(), capturePrivateBytes.Load(), captureTransportReads.Load(), captureTransportBytes.Load(), stateTransactions.Load(), stateCommits.Load(), stateRollbacks.Load()}
}
func (m CaptureMetrics) Since(b CaptureMetrics) CaptureMetrics {
	return CaptureMetrics{m.SourceReads - b.SourceReads, m.SourceHashBytes - b.SourceHashBytes, m.PrivateVerificationReads - b.PrivateVerificationReads, m.PrivateVerificationBytes - b.PrivateVerificationBytes, m.TransportHashReads - b.TransportHashReads, m.TransportHashBytes - b.TransportHashBytes, m.Transactions - b.Transactions, m.CommittedTransactions - b.CommittedTransactions, m.RolledBackTransactions - b.RolledBackTransactions}
}
