package backend

import (
	"context"
	"log"
	"time"
)


type LiveView interface {
	RecordUserMessage(targetAgentID string, message string)
}

func SendUserMessageToAgent(
	ctx context.Context,
	coordinator Coordinator,
	liveView LiveView,
	targetAgentID string,
	message string,
	notifyChanged func(),
	waitForDelivery bool,
) bool {
	if ctx.Err() != nil {
		return false
	}

	deliver := func(deliverCtx context.Context) (bool, error) {
		payload := map[string]interface{}{
			"from":    "user",
			"content": message,
			"type":    "instruction",
		}
		delivered, err := coordinator.Send(targetAgentID, payload)
		if err != nil {
			return false, err
		}
		if delivered {
			if liveView != nil {
				liveView.RecordUserMessage(targetAgentID, message)
			}
			if notifyChanged != nil {
				notifyChanged()
			}
		}
		return delivered, nil
	}

	if waitForDelivery {
		deliverCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()

		delivered, err := deliver(deliverCtx)
		if err != nil {
			preview := message
			if len(preview) > 50 {
				preview = preview[:47] + "..."
			}
			log.Printf("TUI user message delivery failed (wait=true) for agent '%s' (msg: %q): %+v", targetAgentID, preview, err)
			return false
		}
		return delivered
	}

	go func() {
		delivered, err := deliver(ctx)
		logDeliveryFailure(delivered, err, targetAgentID, message)
	}()

	return true
}

func logDeliveryFailure(delivered bool, err error, targetAgentID string, message string) {
	preview := message
	if len(preview) > 50 {
		preview = preview[:47] + "..."
	}
	if err != nil {
		log.Printf("TUI user message delivery failed for agent '%s' (msg: %q): %+v", targetAgentID, preview, err)
		return
	}
	if !delivered {
		log.Printf("TUI user message was not persisted to the SDK session for agent '%s'", targetAgentID)
	}
}
