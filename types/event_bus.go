package types

import (
	"context"
	"fmt"

	cmn "github.com/XunleiBlockchain/tc-libs/common"
	"github.com/XunleiBlockchain/tc-libs/log"
	tmpubsub "github.com/XunleiBlockchain/tc-libs/pubsub"
	tmquery "github.com/XunleiBlockchain/tc-libs/pubsub/query"
)

const defaultCapacity = 0

const (
	// EventTypeKey is a reserved key, used to specify event type in tags.
	EventTypeKey = "th.event"
)

// Reserved event types
const (
	EventNewBlock       = "NewBlock"
	EventNewBlockHeader = "NewBlockHeader"
	EventLog            = "Log"
)

///////////////////////////////////////////////////////////////////////////////
// Event type
///////////////////////////////////////////////////////////////////////////////

type THEventData interface {
}

// Most event messages are basic types (a block, a transaction)
// but some (an input to a call tx or a receive) are more exotic

type EventDataNewBlock struct {
	Block interface{} `json:"block"`
}

type EventDataNewBlockHeader struct {
	Header interface{} `json:"header"`
}

type EventDataLog struct {
	Logs []*Log `json:"logs"`
}

///////////////////////////////////////////////////////////////////////////////
// Subscribe event
///////////////////////////////////////////////////////////////////////////////

var (
	EventQueryNewBlock       = QueryForEvent(EventNewBlock)
	EventQueryNewBlockHeader = QueryForEvent(EventNewBlockHeader)
	EventQueryLog            = QueryForEvent(EventLog)
)

func QueryForEvent(eventType string) tmpubsub.Query {
	return tmquery.MustParse(fmt.Sprintf("%s='%s'", EventTypeKey, eventType))
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

// EventBus is a common bus for all events going through the system. All calls
// are proxied to underlying pubsub server. All events must be published using
// EventBus to ensure correct data types.
type EventBus struct {
	cmn.BaseService
	pubsub *tmpubsub.Server
}

// NewEventBus returns a new event bus.
func NewEventBus() *EventBus {
	return NewEventBusWithBufferCapacity(defaultCapacity)
}

func NewEventBusWithLogger(l log.Logger) *EventBus {
	eb := NewEventBus()
	eb.SetLogger(l)
	return eb
}

// NewEventBusWithBufferCapacity returns a new event bus with the given buffer capacity.
func NewEventBusWithBufferCapacity(cap int) *EventBus {
	// capacity could be exposed later if needed
	pubsub := tmpubsub.NewServer(tmpubsub.BufferCapacity(cap))
	b := &EventBus{pubsub: pubsub}
	b.BaseService = *cmn.NewBaseService(nil, "EventBus", b)
	return b
}

func (b *EventBus) SetLogger(l log.Logger) {
	b.BaseService.SetLogger(l)
	b.pubsub.SetLogger(l.With("module", "pubsub"))
}

func (b *EventBus) OnStart() error {
	return b.pubsub.Start()
}

func (b *EventBus) OnStop() {
	b.pubsub.Stop()
}

func (b *EventBus) Subscribe(ctx context.Context, subscriber string, query tmpubsub.Query, out chan<- interface{}) error {
	return b.pubsub.Subscribe(ctx, subscriber, query, out)
}

func (b *EventBus) Unsubscribe(ctx context.Context, subscriber string, query tmpubsub.Query) error {
	return b.pubsub.Unsubscribe(ctx, subscriber, query)
}

func (b *EventBus) UnsubscribeAll(ctx context.Context, subscriber string) error {
	return b.pubsub.UnsubscribeAll(ctx, subscriber)
}

func (b *EventBus) Publish(eventType string, eventData THEventData) error {
	ctx := context.Background()
	b.pubsub.PublishWithTags(ctx, eventData, tmpubsub.NewTagMap(map[string]string{EventTypeKey: eventType}))
	return nil
}

func (b *EventBus) PublishEventNewBlock(event EventDataNewBlock) error {
	return b.Publish(EventNewBlock, event)
}

func (b *EventBus) PublishEventNewBlockHeader(event EventDataNewBlockHeader) error {
	return b.Publish(EventNewBlockHeader, event)
}

func (b *EventBus) PublishEventLog(event EventDataLog) error {
	return b.Publish(EventLog, event)
}
