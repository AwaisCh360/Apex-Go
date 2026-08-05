package backend

const (
	ProtocolVersion         = 3
	MaxCommandBytes         = 64 * 1024
	MaxCollectionFrameBytes = 4 * 1024 * 1024
)

var ProtocolCapabilities = []string{
	"state-revisions",
	"collection-deltas",
	"structured-command-errors",
	"agents-collection",
}

type ProtocolHandshakeError struct {
	Message string
}

func (e *ProtocolHandshakeError) Error() string {
	return e.Message
}

type EnvelopeMessage struct {
	Version   int                    `json:"version"`
	Type      string                 `json:"type"`
	Payload   map[string]interface{} `json:"payload"`
	RequestID string                 `json:"request_id,omitempty"`
}

func Envelope(messageType string, payload map[string]interface{}, requestID string) EnvelopeMessage {
	return EnvelopeMessage{
		Version:   ProtocolVersion,
		Type:      messageType,
		Payload:   payload,
		RequestID: requestID,
	}
}
