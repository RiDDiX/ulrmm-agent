// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strconv"
	"sync/atomic"
	"time"
)

// agent-wmi with no COM, so the Linux test run covers them.

var (
	errWMITimeout = errors.New("wmi query timed out")
	errWMIBusy    = errors.New("an abandoned wmi query is still running")
)

// wmiAbandoned counts queries that overran their timeout and still run. The
// WMI library serialises all queries behind one lock, so anything started
// while one of them hangs would only queue up behind it.
var wmiAbandoned atomic.Int32

// wmiBounded runs q with a deadline. A panic inside q (the library type
// asserts on array elements) comes back as an error instead of killing the
// agent. On timeout q is left running and later calls fail fast until it
// returns.
func wmiBounded[T any](d time.Duration, q func() (T, error)) (T, error) {
	var zero T
	if wmiAbandoned.Load() > 0 {
		return zero, errWMIBusy
	}
	type result struct {
		v   T
		err error
	}
	ch := make(chan result, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				ch <- result{err: fmt.Errorf("wmi panic: %v", r)}
			}
		}()
		v, err := q()
		ch <- result{v, err}
	}()

	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case r := <-ch:
		return r.v, r.err
	case <-t.C:
		wmiAbandoned.Add(1)
		go func() {
			<-ch
			wmiAbandoned.Add(-1)
		}()
		return zero, errWMITimeout
	}
}

// wmiRows turns the instances of one class into the stored shape: one
// element per instance, each a one-element list holding the object. The
// JSON round trip yields the generic forms the server keeps in wmi_detail:
// numbers as float64, times as RFC 3339 text, unset lists as null.
func wmiRows(instances interface{}) []interface{} {
	out := []interface{}{}
	b, err := json.Marshal(instances)
	if err != nil {
		return out
	}
	var objs []map[string]interface{}
	if json.Unmarshal(b, &objs) != nil {
		return out
	}
	for _, o := range objs {
		out = append(out, []interface{}{o})
	}
	return out
}

// wmiReadAs lists properties WMI reports in another type than the wire
// struct has: the base board's real32 Weight and Width (int32 fields), the
// video controller's uint16 array AcceleratorCapabilities (a string list).
// They are read in WMI's type and converted back, the wire types stay.
// WMI hands uint16 arrays over as VT_I4 elements, and the library fills
// those only into a signed slice (an unsigned one panics on them).
var wmiReadAs = map[string]map[string]reflect.Type{
	"Win32_BaseBoard": {
		"Weight": reflect.TypeOf(float32(0)),
		"Width":  reflect.TypeOf(float32(0)),
	},
	"Win32_VideoController": {
		"AcceleratorCapabilities": reflect.TypeOf([]int32(nil)),
	},
}

// wmiMirror is t with the fields in as swapped to the given types.
func wmiMirror(t reflect.Type, as map[string]reflect.Type) reflect.Type {
	if len(as) == 0 {
		return t
	}
	fields := make([]reflect.StructField, t.NumField())
	for i := range fields {
		f := t.Field(i)
		fields[i] = reflect.StructField{Name: f.Name, Type: f.Type, Tag: f.Tag}
		if typ, ok := as[f.Name]; ok {
			fields[i].Type = typ
		}
	}
	return reflect.StructOf(fields)
}

// wmiConvertRows turns field in the rows of wmiRows back into the shape
// the wire type want gives it.
func wmiConvertRows(rows []interface{}, field string, want reflect.Type) {
	for _, r := range rows {
		l, ok := r.([]interface{})
		if !ok || len(l) == 0 {
			continue
		}
		if m, ok := l[0].(map[string]interface{}); ok {
			if v, ok := m[field]; ok {
				m[field] = wmiConvert(v, want)
			}
		}
	}
}

// wmiConvert: numbers in a string list become their text, a fraction in an
// integer field is cut to its whole part.
func wmiConvert(v interface{}, want reflect.Type) interface{} {
	switch k := want.Kind(); {
	case k == reflect.Slice && want.Elem().Kind() == reflect.String:
		l, ok := v.([]interface{})
		if !ok {
			return v
		}
		out := make([]interface{}, len(l))
		for i, e := range l {
			if f, ok := e.(float64); ok {
				out[i] = strconv.FormatFloat(f, 'f', -1, 64)
			} else {
				out[i] = e
			}
		}
		return out
	case k >= reflect.Int && k <= reflect.Uint64:
		if f, ok := v.(float64); ok {
			return math.Trunc(f)
		}
	}
	return v
}
