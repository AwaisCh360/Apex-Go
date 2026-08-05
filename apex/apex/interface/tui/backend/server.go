package backend

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"reflect"
	"sync"
	"time"
)

const (
	CollectionPayloadTarget  = MaxCollectionFrameBytes - 16*1024
	HandshakeTimeout = 10 * time.Second
)



var collections = []string{"agents", "events", "vulnerabilities"}
var collectionItemLimits = map[string]int{
	"events":          5000,
	"vulnerabilities": 1000,
}

// Controller defines the interface expected from the TUI controller.
type Controller interface {
	SetChangeCallback(ChangeCallback)
	Handle(command string, payload map[string]interface{}) (map[string]interface{}, error)
	Snapshot() map[string]interface{}
	Collection(name string) ([]map[string]interface{}, error)
	CollectionSnapshot(name string) (sourceCursor *int, items []map[string]interface{}, err error)
	CollectionChanges(name string, cursor int) (nextCursor int, items []map[string]interface{}, err error)
}

type CollectionState struct {
	Revision     int
	Bootstrapped bool
	Order        []string
	Items        map[string]map[string]interface{}
	Fingerprints map[string]string
	SourceCursor *int
}

// TuiBackendServer serves one TUI child over an authenticated, connected socket.
type TuiBackendServer struct {
	controller       Controller
	conn             net.Conn
	cancel           context.CancelFunc
	ctx              context.Context
	broadcastEvent   chan struct{}
	writeMutex       sync.Mutex
	syncMutex        sync.Mutex
	stateRevision    int
	stateFingerprint string
	colls            map[string]*CollectionState
	seenRequestIDs   map[string]struct{}
	requestIDOrder   []string
	Activated        bool
	wg               sync.WaitGroup
}

func NewTuiBackendServer(controller Controller) *TuiBackendServer {
	s := &TuiBackendServer{
		controller:     controller,
		broadcastEvent: make(chan struct{}, 1),
		colls:          make(map[string]*CollectionState),
		seenRequestIDs: make(map[string]struct{}),
		requestIDOrder: make([]string, 0),
	}
	for _, name := range collections {
		s.colls[name] = &CollectionState{
			Order:        make([]string, 0),
			Items:        make(map[string]map[string]interface{}),
			Fingerprints: make(map[string]string),
		}
	}
	controller.SetChangeCallback(s.NotifyChanged)
	return s
}

func (s *TuiBackendServer) Start(conn net.Conn) error {
	if s.conn != nil {
		return errors.New("TUI backend is already started")
	}
	s.conn = conn

	helloMsg := Envelope("hello", map[string]interface{}{"capabilities": ProtocolCapabilities}, "")
	if err := s.send(helloMsg); err != nil {
		return fmt.Errorf("failed to send hello: %w", err)
	}

	readyCh := make(chan error, 1)
	go func() {
		readyCh <- s.receiveReady()
	}()

	select {
	case err := <-readyCh:
		if err != nil {
			return fmt.Errorf("TUI closed during protocol handshake: %w", err)
		}
	case <-time.After(HandshakeTimeout):
		return errors.New("timed out waiting for TUI protocol ready")
	}

	s.Activated = true
	ctx, cancel := context.WithCancel(context.Background())
	s.ctx = ctx
	s.cancel = cancel

	s.wg.Add(2)
	go s.readLoop()
	go s.broadcastLoop()
	s.NotifyChanged()

	return nil
}

func (s *TuiBackendServer) Close() error {
	if s.cancel != nil {
		s.cancel()
	}
	s.closeSocket()
	s.wg.Wait()
	return nil
}

func (s *TuiBackendServer) closeSocket() {
	s.writeMutex.Lock()
	defer s.writeMutex.Unlock()
	if s.conn != nil {
		s.conn.Close()
		s.conn = nil
	}
}

func (s *TuiBackendServer) NotifyChanged() {
	if s.Activated {
		select {
		case s.broadcastEvent <- struct{}{}:
		default:
		}
	}
}

func (s *TuiBackendServer) readExactly(size uint32) ([]byte, error) {
	if s.conn == nil {
		return nil, errors.New("TUI IPC connection is closed")
	}
	buf := make([]byte, size)
	_, err := io.ReadFull(s.conn, buf)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func (s *TuiBackendServer) readFrame(maximum uint32) ([]byte, error) {
	header, err := s.readExactly(4)
	if err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(header)
	if size == 0 || size > maximum {
		return nil, fmt.Errorf("invalid TUI IPC frame size: %d", size)
	}
	return s.readExactly(size)
}

func (s *TuiBackendServer) receiveReady() error {
	raw, err := s.readFrame(MaxCommandBytes)
	if err != nil {
		return err
	}
	var message map[string]interface{}
	if err := json.Unmarshal(raw, &message); err != nil {
		return err
	}
	if v, ok := message["version"].(float64); !ok || int(v) != ProtocolVersion {
		return fmt.Errorf("TUI protocol mismatch: expected v%d", ProtocolVersion)
	}
	if message["type"] != "ready" {
		return errors.New("TUI protocol handshake expected ready")
	}
	payload, ok := message["payload"].(map[string]interface{})
	if !ok {
		return errors.New("TUI ready payload must be an object")
	}
	caps, ok := payload["capabilities"].([]interface{})
	if !ok {
		return errors.New("TUI protocol capability mismatch")
	}
	if len(caps) != len(ProtocolCapabilities) {
		return errors.New("TUI protocol capability mismatch")
	}
	for i, cap := range caps {
		strCap, ok := cap.(string)
		if !ok || strCap != ProtocolCapabilities[i] {
			return errors.New("TUI protocol capability mismatch")
		}
	}
	return nil
}

func (s *TuiBackendServer) readLoop() {
	defer s.wg.Done()
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		raw, err := s.readFrame(MaxCommandBytes)
		if err != nil {
			if s.cancel != nil {
				s.cancel()
			}
			s.closeSocket()
			return
		}

		response, resync, err := s.handleMessage(raw)
		if response != nil {
			s.sendCommandResponse(*response)
		}
		if resync != "" {
			if err := s.resyncCollection(resync); err != nil {
				if s.cancel != nil {
					s.cancel()
				}
				s.closeSocket()
				return
			}
		}
	}
}

type InvalidRequestError struct {
	msg string
}

func (e *InvalidRequestError) Error() string { return e.msg }

type CommandFailedError struct {
	msg string
}

func (e *CommandFailedError) Error() string { return e.msg }

func (s *TuiBackendServer) decodeMessage(raw []byte) (string, string, map[string]interface{}, error) {
	var preliminary interface{}
	if err := json.Unmarshal(raw, &preliminary); err != nil {
		return "", "", nil, err // Let caller classify it
	}
	message, ok := preliminary.(map[string]interface{})
	if !ok {
		return "", "", nil, &InvalidRequestError{msg: "message must be an object"} // Type error
	}
	
	reqIDVal, ok := message["request_id"].(string)
	if !ok || reqIDVal == "" {
		return "", "", nil, &InvalidRequestError{msg: "command request_id must be a non-empty string"}
	}
	
	versionVal, ok := message["version"].(float64)
	if !ok || int(versionVal) != ProtocolVersion {
		return "", "", nil, &InvalidRequestError{msg: fmt.Sprintf("unsupported protocol version; expected %d", ProtocolVersion)}
	}
	
	cmdVal, ok := message["type"].(string)
	if !ok {
		return "", "", nil, &InvalidRequestError{msg: "invalid command envelope"}
	}
	if len(cmdVal) > 128 {
		return "", "", nil, &InvalidRequestError{msg: "command name exceeds 128 characters"}
	}
	
	payloadVal, ok := message["payload"]
	if !ok {
		payloadVal = make(map[string]interface{})
	}
	payload, ok := payloadVal.(map[string]interface{})
	if !ok {
		return "", "", nil, &InvalidRequestError{msg: "invalid command envelope"}
	}
	
	return reqIDVal, cmdVal, payload, nil
}

func (s *TuiBackendServer) handleMessage(raw []byte) (*EnvelopeMessage, string, error) {
	var requestID string
	var command string
	
	var preliminary map[string]interface{}
	if err := json.Unmarshal(raw, &preliminary); err == nil {
		if reqID, ok := preliminary["request_id"].(string); ok {
			requestID = reqID
		}
		if cmd, ok := preliminary["type"].(string); ok {
			command = cmd
			if len(command) > 128 {
				command = command[:128]
			}
		}
	}

	reqID, cmd, payload, decodeErr := s.decodeMessage(raw)
	if decodeErr == nil {
		requestID = reqID
		command = cmd
	}

	if decodeErr != nil {
		if requestID == "" {
			// A malformed envelope without an ID cannot be correlated.
			return nil, "", nil
		}
		return s.errorResponse(command, requestID, decodeErr), "", nil
	}
	
	if requestID != "" {
		if _, exists := s.seenRequestIDs[requestID]; exists {
			return s.errorResponse(command, requestID, &InvalidRequestError{msg: "duplicate request_id"}), "", nil
		}
		s.seenRequestIDs[requestID] = struct{}{}
		s.requestIDOrder = append(s.requestIDOrder, requestID)
		if len(s.requestIDOrder) > 10000 {
			delete(s.seenRequestIDs, s.requestIDOrder[0])
			s.requestIDOrder = s.requestIDOrder[1:]
		}
	}



	var resync string
	var result map[string]interface{}
	var err error

	if command == "collection.resync" {
		col, ok := payload["collection"].(string)
		if !ok || !isValidCollection(col) {
			return s.errorResponse(command, requestID, &InvalidRequestError{msg: "invalid collection"}), "", nil
		}
		result = map[string]interface{}{"collection": col, "resyncing": true}
		resync = col
	} else {
		result, err = s.controller.Handle(command, payload)
	}

	if err != nil {
		return s.errorResponse(command, requestID, err), "", nil
	}

	env := Envelope("command_result", map[string]interface{}{
		"ok":      true,
		"command": command,
		"result":  result,
	}, requestID)

	return &env, resync, nil
}

func isValidCollection(col string) bool {
	for _, c := range collections {
		if c == col {
			return true
		}
	}
	return false
}

func (s *TuiBackendServer) structuredError(err error) map[string]interface{} {
	if _, ok := err.(*InvalidRequestError); ok {
		return map[string]interface{}{"code": "invalid_request", "message": err.Error(), "retryable": false}
	}
	if _, ok := err.(*CommandFailedError); ok {
		return map[string]interface{}{"code": "command_failed", "message": err.Error(), "retryable": false}
	}
	
	if _, ok := err.(*json.SyntaxError); ok {
		return map[string]interface{}{"code": "invalid_request", "message": err.Error(), "retryable": false}
	}
	if _, ok := err.(*json.UnmarshalTypeError); ok {
		return map[string]interface{}{"code": "invalid_request", "message": err.Error(), "retryable": false}
	}
	
	if _, ok := err.(*os.PathError); ok {
		return map[string]interface{}{"code": "persistence_error", "message": err.Error(), "retryable": true}
	}
	
	return map[string]interface{}{
		"code":      "internal_error",
		"message":   "The command failed unexpectedly",
		"retryable": true,
	}
}

func (s *TuiBackendServer) errorResponse(command, requestID string, err error) *EnvelopeMessage {
	env := Envelope("command_result", map[string]interface{}{
		"ok":      false,
		"command": command,
		"error":   s.structuredError(err),
	}, requestID)
	return &env
}

func (s *TuiBackendServer) sanitizeWireValue(value interface{}) interface{} {
	if value == nil {
		return nil
	}
	val := reflect.ValueOf(value)
	switch val.Kind() {
	case reflect.String:
		return SanitizeTerminalText(val.String())
	case reflect.Map:
		sanitized := make(map[string]interface{})
		for _, key := range val.MapKeys() {
			strKey := fmt.Sprintf("%v", key.Interface())
			sanitized[SanitizeTerminalText(strKey)] = s.sanitizeWireValue(val.MapIndex(key).Interface())
		}
		return sanitized
	case reflect.Slice, reflect.Array:
		sanitized := make([]interface{}, val.Len())
		for i := 0; i < val.Len(); i++ {
			sanitized[i] = s.sanitizeWireValue(val.Index(i).Interface())
		}
		return sanitized
	default:
		return value
	}
}

func (s *TuiBackendServer) encode(message EnvelopeMessage) ([]byte, error) {
	if message.Payload != nil {
		message.Payload = s.sanitizeWireValue(message.Payload).(map[string]interface{})
	}
	raw, err := json.Marshal(message)
	if err != nil {
		return nil, err
	}
	max := MaxCommandBytes
	if message.Type == "collection_bootstrap" || message.Type == "collection_delta" {
		max = MaxCollectionFrameBytes
	}
	if len(raw) > max {
		return nil, fmt.Errorf("TUI IPC message exceeds %d bytes", max)
	}
	return raw, nil
}

func (s *TuiBackendServer) send(message EnvelopeMessage) error {
	raw, err := s.encode(message)
	if err != nil {
		return err
	}
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(raw)))
	framed := append(header, raw...)

	s.writeMutex.Lock()
	defer s.writeMutex.Unlock()
	if s.conn == nil {
		return errors.New("TUI IPC connection is closed")
	}
	s.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err = s.conn.Write(framed)
	return err
}

func (s *TuiBackendServer) sendCommandResponse(response EnvelopeMessage) {
	if err := s.send(response); err != nil {
		cmd, _ := response.Payload["command"].(string)
		errResp := Envelope("command_result", map[string]interface{}{
			"ok":      false,
			"command": cmd,
			"error":   s.structuredError(err),
		}, response.RequestID)
		s.send(errResp)
		log.Printf("Failed to deliver command response: %v", err)
	}
}

func fingerprint(value interface{}) string {
	b, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprintf("%#v", value)
	}
	return string(b)
}

func (s *TuiBackendServer) sendStateIfChanged() error {
	state := s.controller.Snapshot()
	fp := fingerprint(state)
	if fp == s.stateFingerprint {
		return nil
	}
	s.stateRevision++
	if err := s.send(Envelope("state", map[string]interface{}{
		"revision": s.stateRevision,
		"state":    state,
	}, "")); err != nil {
		s.stateRevision--
		return err
	}
	s.stateFingerprint = fp
	return nil
}

func collectionValues(items []map[string]interface{}) ([]string, map[string]map[string]interface{}, map[string]string) {
	order := make([]string, 0)
	byID := make(map[string]map[string]interface{})
	fingerprints := make(map[string]string)
	for _, item := range items {
		if id, ok := item["id"].(string); ok && id != "" {
			order = append(order, id)
			byID[id] = item
			fingerprints[id] = fingerprint(item)
		}
	}
	return order, byID, fingerprints
}

func (s *TuiBackendServer) sendCollectionFrames(messageType string, fixed map[string]interface{}, fieldName string, values []map[string]interface{}) error {
	cursor := 0
	if len(values) == 0 {
		payload := make(map[string]interface{})
		for k, v := range fixed {
			payload[k] = v
		}
		payload["cursor"] = 0
		payload["next_cursor"] = 0
		payload["done"] = true
		payload[fieldName] = []interface{}{}
		return s.send(Envelope(messageType, payload, ""))
	}

	for cursor < len(values) {
		chunk := make([]map[string]interface{}, 0)
		nextCursor := cursor

		emptyPayload := make(map[string]interface{})
		for k, v := range fixed {
			emptyPayload[k] = v
		}
		emptyPayload["cursor"] = cursor
		emptyPayload["next_cursor"] = cursor
		emptyPayload["done"] = false
		emptyPayload[fieldName] = []interface{}{}

		emptyEnv := Envelope(messageType, emptyPayload, "")
		b, _ := json.Marshal(emptyEnv)
		estimatedSize := len(b)

		for nextCursor < len(values) {
			item := values[nextCursor]
			itemB, _ := json.Marshal(item)
			itemSize := len(itemB)
			if estimatedSize+itemSize+1 > CollectionPayloadTarget && len(chunk) > 0 {
				break
			}
			chunk = append(chunk, item)
			estimatedSize += itemSize + 1
			nextCursor++
		}

		payload := make(map[string]interface{})
		for k, v := range fixed {
			payload[k] = v
		}
		payload["cursor"] = cursor
		payload["next_cursor"] = nextCursor
		payload["done"] = nextCursor == len(values)
		payload[fieldName] = chunk

		if err := s.send(Envelope(messageType, payload, "")); err != nil {
			return err
		}
		cursor = nextCursor
	}
	return nil
}

func (s *TuiBackendServer) sendCollectionBootstrap(name string, items []map[string]interface{}) error {
	state := s.colls[name]
	var sourceCursor *int
	var projected []map[string]interface{}

	if items == nil {
		cursor, items, err := s.controller.CollectionSnapshot(name)
		if err != nil {
			return err
		}
		sourceCursor = cursor
		projected = items
	} else {
		projected = items
	}

	order, byID, fingerprints := collectionValues(projected)
	revision := state.Revision + 1

	orderedItems := make([]map[string]interface{}, 0, len(order))
	for _, id := range order {
		orderedItems = append(orderedItems, byID[id])
	}

	if err := s.sendCollectionFrames("collection_bootstrap", map[string]interface{}{
		"collection": name,
		"revision":   revision,
	}, "items", orderedItems); err != nil {
		return err
	}

	state.Revision = revision
	state.Bootstrapped = true
	state.Order = order
	state.Items = byID
	state.Fingerprints = fingerprints
	state.SourceCursor = sourceCursor
	return nil
}

func (s *TuiBackendServer) sendCollectionIfChanged(name string) error {
	state := s.colls[name]

	if name == "events" && state.Bootstrapped && state.SourceCursor != nil {
		nextCursor, items, err := s.controller.CollectionChanges(name, *state.SourceCursor)
		if err != nil {
			return err
		}
		if nextCursor == *state.SourceCursor {
			return nil
		}

		operations := make([]map[string]interface{}, 0)
		for _, item := range items {
			id, ok := item["id"].(string)
			if !ok || id == "" {
				continue
			}
			operations = append(operations, map[string]interface{}{"op": "upsert", "item": item})
			if _, exists := state.Items[id]; !exists {
				state.Order = append(state.Order, id)
			}
			state.Items[id] = item
			state.Fingerprints[id] = fingerprint(item)
		}

		limit := collectionItemLimits[name]
		for len(state.Order) > limit {
			removedID := state.Order[0]
			state.Order = state.Order[1:]
			delete(state.Items, removedID)
			delete(state.Fingerprints, removedID)
			operations = append(operations, map[string]interface{}{"op": "delete", "id": removedID})
		}

		if len(operations) > 0 {
			revision := state.Revision + 1
			if err := s.sendCollectionFrames("collection_delta", map[string]interface{}{
				"collection":    name,
				"base_revision": state.Revision,
				"revision":      revision,
			}, "operations", operations); err != nil {
				return err
			}
			state.Revision = revision
		}
		state.SourceCursor = &nextCursor
		return nil
	}

	projected, err := s.controller.Collection(name)
	if err != nil {
		return err
	}
	order, byID, fingerprints := collectionValues(projected)

	if !state.Bootstrapped {
		if name == "events" {
			return s.sendCollectionBootstrap(name, nil)
		} else {
			return s.sendCollectionBootstrap(name, projected)
		}
	}

	sameOrder := len(order) == len(state.Order)
	if sameOrder {
		for i := range order {
			if order[i] != state.Order[i] {
				sameOrder = false
				break
			}
		}
	}

	sameFingerprints := true
	if sameOrder {
		for k, v := range fingerprints {
			if state.Fingerprints[k] != v {
				sameFingerprints = false
				break
			}
		}
	}

	if sameOrder && sameFingerprints {
		return nil
	}

	retained := make([]string, 0)
	for _, id := range state.Order {
		if _, exists := byID[id]; exists {
			retained = append(retained, id)
		}
	}
	
	expectedOrder := retained
	for _, id := range order {
		if _, exists := state.Items[id]; !exists {
			expectedOrder = append(expectedOrder, id)
		}
	}

	orderMatch := len(order) == len(expectedOrder)
	if orderMatch {
		for i := range order {
			if order[i] != expectedOrder[i] {
				orderMatch = false
				break
			}
		}
	}

	if !orderMatch {
		return s.sendCollectionBootstrap(name, projected)
	}

	operations := make([]map[string]interface{}, 0)
	for _, id := range state.Order {
		if _, exists := byID[id]; !exists {
			operations = append(operations, map[string]interface{}{"op": "delete", "id": id})
		}
	}
	for _, id := range order {
		if fingerprints[id] != state.Fingerprints[id] {
			operations = append(operations, map[string]interface{}{"op": "upsert", "item": byID[id]})
		}
	}

	if len(operations) == 0 {
		return s.sendCollectionBootstrap(name, projected)
	}

	revision := state.Revision + 1
	if err := s.sendCollectionFrames("collection_delta", map[string]interface{}{
		"collection":    name,
		"base_revision": state.Revision,
		"revision":      revision,
	}, "operations", operations); err != nil {
		return err
	}

	state.Revision = revision
	state.Order = order
	state.Items = byID
	state.Fingerprints = fingerprints
	return nil
}

func (s *TuiBackendServer) flushUpdates() error {
	s.syncMutex.Lock()
	defer s.syncMutex.Unlock()
	if err := s.sendStateIfChanged(); err != nil {
		return err
	}
	for _, name := range collections {
		if err := s.sendCollectionIfChanged(name); err != nil {
			return err
		}
	}
	return nil
}

func (s *TuiBackendServer) resyncCollection(name string) error {
	s.syncMutex.Lock()
	defer s.syncMutex.Unlock()
	return s.sendCollectionBootstrap(name, nil)
}

func (s *TuiBackendServer) broadcastLoop() {
	defer s.wg.Done()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-s.broadcastEvent:
			time.Sleep(50 * time.Millisecond)
			if err := s.flushUpdates(); err != nil {
				log.Printf("TUI projection could not be framed: %v", err)
				if s.cancel != nil {
					s.cancel()
				}
				s.closeSocket()
				return
			}
		}
	}
}
