package output_store

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/google/uuid"
)

const (
	TruncationNotice     = "[... %d lines (%d bytes) truncated ...]"
	WorkspaceSpillNotice = "[... %d lines (%d bytes) truncated — full output saved to %s in the sandbox; read it with exec_command (e.g. `sed -n`, `grep`, `cat`) ...]"
	WorkspaceSpillDir    = "/workspace/.apex/tool-output"
)

var sampleWorkspacePath = fmt.Sprintf("%s/%s.txt", WorkspaceSpillDir, strings.Repeat("0", 32))

type SpillWriter func(ctx context.Context, id string, content string) (string, error)

var (
	spillMu     sync.RWMutex
	spillWriter SpillWriter
)

func ConfigureSpillWriter(writer SpillWriter) {
	spillMu.Lock()
	defer spillMu.Unlock()
	spillWriter = writer
}

func byteLen(text string) int {
	return len(text)
}

func takePrefix(text string, maxBytes int) string {
	budget := 0
	var out strings.Builder
	for _, char := range text {
		size := utf8.RuneLen(char)
		if budget+size > maxBytes {
			break
		}
		out.WriteRune(char)
		budget += size
	}
	return out.String()
}

func takeSuffix(text string, maxBytes int) string {
	budget := 0
	runes := []rune(text)
	var outRunes []rune
	for i := len(runes) - 1; i >= 0; i-- {
		char := runes[i]
		size := utf8.RuneLen(char)
		if budget+size > maxBytes {
			break
		}
		outRunes = append(outRunes, char)
		budget += size
	}
	// Reverse the collected suffix runes
	for i, j := 0, len(outRunes)-1; i < j; i, j = i+1, j-1 {
		outRunes[i], outRunes[j] = outRunes[j], outRunes[i]
	}
	return string(outRunes)
}

func headTail(text string, maxLines, maxBytes int, noticeTemplates ...string) (head, tail string, droppedLines, droppedBytes int, ok bool) {
	lines := strings.Split(text, "\n")
	totalBytes := byteLen(text)

	if len(lines) <= maxLines && totalBytes <= maxBytes {
		return "", "", 0, 0, false
	}

	noticeOverhead := 0
	for _, template := range noticeTemplates {
		// Use dummy values to compute worst-case length
		formatted := fmt.Sprintf(template, len(lines), totalBytes, sampleWorkspacePath)
		size := byteLen(formatted)
		if size > noticeOverhead {
			noticeOverhead = size
		}
	}
	noticeOverhead += 4 // for the "\n\n" separators

	byteBudget := maxBytes - noticeOverhead
	if byteBudget < 2 {
		byteBudget = 2
	}

	headLines := maxLines / 2
	if headLines < 1 {
		headLines = 1
	}
	if headLines > len(lines) {
		headLines = len(lines)
	}
	tailLines := maxLines - headLines
	if tailLines > len(lines)-headLines {
		tailLines = len(lines) - headLines
	}

	head = strings.Join(lines[:headLines], "\n")
	tail = ""
	if tailLines > 0 {
		tail = strings.Join(lines[len(lines)-tailLines:], "\n")
	}

	halfBytes := byteBudget / 2
	if halfBytes < 1 {
		halfBytes = 1
	}

	if byteLen(head) > halfBytes {
		head = takePrefix(head, halfBytes)
	}
	if tail != "" && byteLen(tail) > halfBytes {
		tail = takeSuffix(tail, halfBytes)
	}

	keptLines := len(strings.Split(head, "\n"))
	if tail != "" {
		keptLines += len(strings.Split(tail, "\n"))
	}

	droppedLines = len(lines) - keptLines
	if droppedLines < 0 {
		droppedLines = 0
	}
	droppedBytes = totalBytes - byteLen(head) - byteLen(tail)
	if droppedBytes < 0 {
		droppedBytes = 0
	}

	return head, tail, droppedLines, droppedBytes, true
}

func joinHeadTail(head, tail, notice string) string {
	if tail != "" {
		return fmt.Sprintf("%s\n\n%s\n\n%s", head, notice, tail)
	}
	return fmt.Sprintf("%s\n\n%s", head, notice)
}

func BoundText(text string, maxLines, maxBytes int) string {
	head, tail, droppedLines, droppedBytes, ok := headTail(text, maxLines, maxBytes, TruncationNotice)
	if !ok {
		return text
	}
	notice := fmt.Sprintf(TruncationNotice, droppedLines, droppedBytes)
	return joinHeadTail(head, tail, notice)
}

func BoundAndStore(ctx context.Context, text string, maxLines, maxBytes int) (string, error) {
	head, tail, droppedLines, droppedBytes, ok := headTail(text, maxLines, maxBytes, WorkspaceSpillNotice, TruncationNotice)
	if !ok {
		return text, nil
	}

	spillMu.RLock()
	writer := spillWriter
	spillMu.RUnlock()

	if writer != nil {
		id := strings.ReplaceAll(uuid.New().String(), "-", "")
		path, err := writer(ctx, id, text)
		if err == nil && path != "" {
			notice := fmt.Sprintf(WorkspaceSpillNotice, droppedLines, droppedBytes, path)
			return joinHeadTail(head, tail, notice), nil
		}
	}

	notice := fmt.Sprintf(TruncationNotice, droppedLines, droppedBytes)
	return joinHeadTail(head, tail, notice), nil
}
