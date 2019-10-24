// Copyright (c) 2018-2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package main

import (
	"bytes"
	"context"
	"fmt"
	"encoding/binary"
	"encoding/gob"
	"net"

	gen "github.com/mcastelino/custom_exporter/jaeger"
	"github.com/mdlayher/vsock"
	"go.opencensus.io/tag"
	"go.opencensus.io/trace"
)

// agentSpan defines span by using opencensus
type agentSpan struct {
	span *trace.Span
}

// The first trace span
var rootSpan *agentSpan

// startSpan starts a new child span of the current span in the context
func startSpan(ctx context.Context, name string) (context.Context, *agentSpan) {
	var a agentSpan
	ctx, a.span = trace.StartSpan(ctx, name)
	return ctx, &a
}

// spanFromContext returns the span stored in a context
func spanFromContext(ctx context.Context) *agentSpan {
	var a agentSpan
	a.span = trace.FromContext(ctx)
	return &a
}

// spanStartSpanWithRemoveParent starts a new child span of the span from the given parent
func spanStartSpanWithRemoteParent(ctx context.Context, name string, parent trace.SpanContext) (context.Context, *agentSpan) {
	a := &agentSpan{}
	ctx, a.span = trace.StartSpanWithRemoteParent(ctx, name, parent)
	return ctx, a
}

// spanNewContext returns a new context with the givien span attached
func spanNewContext(parent context.Context, s *agentSpan) context.Context {
	return trace.NewContext(parent, s.span)
}

// finish will end the span
func (a *agentSpan) finish() {
	a.span.End()
}

//spanAnnotate adds an annotation with attributes.
func (a *agentSpan) spanAnnotate(attributes []trace.Attribute, str string) {
	a.span.Annotate(attributes, str)
}

// setTag sets the name of the span, if it is recording events
func setTag(name string, value interface{})(key tag.Key, err error) {
	key, err = tag.NewKey(fmt.Sprintf("%s=%v" ,name, value))
	return key, err
}

// Defining the exporter
type customTraceExporter struct {
	Conn net.Conn
}

// Flush waits for exported trace spans to be uploaded
func (ce *customTraceExporter) Flush() {
}

// Close ends the exporter
func (ce *customTraceExporter) Close() {
	ce.Conn.Close()
}

// Init implements vsock
func (ce *customTraceExporter) Init() {
	c, err := vsock.Dial(2, 1024)
	if err != nil {
		agentLog.WithError(err).Warn("Dial error")
	}
	ce.Conn = c
}

// Configure sampler & create exporter
func createExporter() {
	// Configure 100% sample rate, otherwise, few traces will be sampled
	trace.ApplyConfig(trace.Config{DefaultSampler: trace.AlwaysSample()})

	ce := &customTraceExporter{}
	ce.Init()
	defer ce.Close()

	// Register exporter to collect tracing data
	trace.RegisterExporter(ce)
}

// ExportSpan is needed to translate Span Data into the data that
// the trace backend accepts
func (ce *customTraceExporter) ExportSpan(sd *trace.SpanData) {
	var network bytes.Buffer
	thriftData := spanDataToThrift(sd)
	enc := gob.NewEncoder(&network)
	if err := enc.Encode(&thriftData); err != nil {
		agentLog.WithError(err).Warn("encode error")
	}

	if _, err := ce.Conn.Write(network.Bytes()); err != nil {
		agentLog.WithError(err).Warn("transmit error")
	}
}

func bytesToInt64(buf []byte) int64 {
	u := binary.BigEndian.Uint64(buf)
	return int64(u)
}

func name(sd *trace.SpanData) string {
	n := sd.Name
	switch sd.SpanKind {
	case trace.SpanKindClient:
		n = "Sent." + n
	case trace.SpanKindServer:
		n = "Recv." + n
	}
	return n
}

func attributeToTag(key string, a interface{}) *gen.Tag {
	var tag *gen.Tag
	switch value := a.(type) {
	case bool:
		tag = &gen.Tag{
			Key:   key,
			VBool: &value,
			VType: gen.TagType_BOOL,
		}
	case string:
		tag = &gen.Tag{
			Key:   key,
			VStr:  &value,
			VType: gen.TagType_STRING,
		}
	case int64:
		tag = &gen.Tag{
			Key:   key,
			VLong: &value,
			VType: gen.TagType_LONG,
		}
	case int32:
		v := int64(value)
		tag = &gen.Tag{
			Key:   key,
			VLong: &v,
			VType: gen.TagType_LONG,
		}
	case float64:
		v := float64(value)
		tag = &gen.Tag{
			Key:     key,
			VDouble: &v,
			VType:   gen.TagType_DOUBLE,
		}
	}
	return tag
}

func spanDataToThrift(data *trace.SpanData) *gen.Span {
	tags := make([]*gen.Tag, 0, len(data.Attributes))
	for k, v := range data.Attributes {
		tag := attributeToTag(k, v)
		if tag != nil {
			tags = append(tags, tag)
		}
	}

	tags = append(tags,
		}
	}

	tags = append(tags,
		attributeToTag("status.code", data.Status.Code),
		attributeToTag("status.message", data.Status.Message),
	)

	var logs []*gen.Log
	for _, a := range data.Annotations {
		fields := make([]*gen.Tag, 0, len(a.Attributes))
		for k, v := range a.Attributes {
			tag := attributeToTag(k, v)
			if tag != nil {
				fields = append(fields, tag)
			}
		}
		fields = append(fields, attributeToTag("message", a.Message))
		logs = append(logs, &gen.Log{
			Timestamp: a.Time.UnixNano() / 1000,
			Fields:    fields,
		})
	}
	var refs []*gen.SpanRef
	for _, link := range data.Links {
		refs = append(refs, &gen.SpanRef{
			TraceIdHigh: bytesToInt64(link.TraceID[0:8]),
			TraceIdLow:  bytesToInt64(link.TraceID[8:16]),
			SpanId:      bytesToInt64(link.SpanID[:]),
		})
	}
	return &gen.Span{
		TraceIdHigh:   bytesToInt64(data.TraceID[0:8]),
		TraceIdLow:    bytesToInt64(data.TraceID[8:16]),
		SpanId:        bytesToInt64(data.SpanID[:]),
		ParentSpanId:  bytesToInt64(data.ParentSpanID[:]),
		OperationName: name(data),
		Flags:         int32(data.TraceOptions),
		StartTime:     data.StartTime.UnixNano() / 1000,
		Duration:      data.EndTime.Sub(data.StartTime).Nanoseconds() / 1000,
		Tags:          tags,
		Logs:          logs,
		References:    refs,
	}
}

func setupTracing(rootSpanName string) (*agentSpan, context.Context) {
	ctx := context.Background()

	createExporter()

	// Create the rootspan
	ctx, span := startSpan(ctx, rootSpanName)
	setTag("source", "agent")
	setTag("root-span", "true")

	// Make the span close at the end
	span.finish()

	if tracing {
		agentLog.Debugf("created root span %v", span)
	}

	// Here we are returning a new context with the given span attached
	ctx = spanNewContext(ctx, span)
	return span, ctx
}

func stopTracing(ctx context.Context) {
	if ctx == nil {
		return
	}

	// here we are returning the span stored in a context
	span := spanFromContext(ctx)
	if span != nil {
		span.finish()
	}
}

// tracer creates a new tracing span based on the specified contex, subsystem
// and name.
func tracer(ctx context.Context, subsystem, name string) (*agentSpan, context.Context) {
	var parent trace.SpanContext
	ctx, span := spanStartSpanWithRemoteParent(ctx, name, parent)

	setTag("subsystem", subsystem)

	// This is slightly confusing: when tracing is disabled, trace spans
	// are still created - but the tracer used is a NOP. Therefore, only
	// display the message when tracing is really enabled.
	if tracing {
		agentLog.Debugf("created span %v", span)
	}

	return span, ctx
}
