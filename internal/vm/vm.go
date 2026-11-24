// Package vm runs instant PromQL queries against VictoriaMetrics (vmsingle):
// "what does the alert's own expression say right now". Read-only API.
package vm

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Client queries one vmsingle.
type Client struct {
	Base string // http://vmsingle-vmstack.monitoring.svc:8428
	HTTP *http.Client
}

// Sample is one series' current value.
type Sample struct {
	Labels map[string]string `json:"labels"`
	Value  string            `json:"value"`
}

// Query runs an instant query and returns up to max samples.
func (c *Client) Query(ctx context.Context, expr string, max int) ([]Sample, error) {
	u := strings.TrimRight(c.Base, "/") + "/api/v1/query?" + url.Values{"query": {expr}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var body struct {
		Status string `json:"status"`
		Error  string `json:"error"`
		Data   struct {
			Result []struct {
				Metric map[string]string `json:"metric"`
				Value  [2]any            `json:"value"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("vm: decode: %w", err)
	}
	if body.Status != "success" {
		return nil, fmt.Errorf("vm: %s", body.Error)
	}
	out := make([]Sample, 0, len(body.Data.Result))
	for _, r := range body.Data.Result {
		v, _ := r.Value[1].(string)
		out = append(out, Sample{Labels: r.Metric, Value: v})
	}
	sort.Slice(out, func(i, j int) bool { return fmt.Sprint(out[i].Labels) < fmt.Sprint(out[j].Labels) })
	if max > 0 && len(out) > max {
		out = out[:max]
	}
	return out, nil
}

// Series is one range-query series: its labels and [unix seconds, value] points.
type Series struct {
	Labels map[string]string `json:"labels"`
	Points [][2]float64      `json:"points"`
}

// QueryRange runs a range query over [start, end] at step and returns up to
// max series (0 = all). NaN and unparsable points are dropped.
func (c *Client) QueryRange(ctx context.Context, expr string, start, end time.Time, step time.Duration, max int) ([]Series, error) {
	q := url.Values{
		"query": {expr},
		"start": {strconv.FormatInt(start.Unix(), 10)},
		"end":   {strconv.FormatInt(end.Unix(), 10)},
		"step":  {strconv.Itoa(int(step.Seconds())) + "s"},
	}
	u := strings.TrimRight(c.Base, "/") + "/api/v1/query_range?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 20 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var body struct {
		Status string `json:"status"`
		Error  string `json:"error"`
		Data   struct {
			Result []struct {
				Metric map[string]string `json:"metric"`
				Values [][2]any          `json:"values"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("vm: decode: %w", err)
	}
	if body.Status != "success" {
		return nil, fmt.Errorf("vm: %s", body.Error)
	}
	out := make([]Series, 0, len(body.Data.Result))
	for _, r := range body.Data.Result {
		s := Series{Labels: r.Metric}
		for _, v := range r.Values {
			ts, _ := v[0].(float64)
			str, _ := v[1].(string)
			f, err := strconv.ParseFloat(str, 64)
			if err != nil || f != f || math.IsInf(f, 0) {
				continue
			}
			s.Points = append(s.Points, [2]float64{ts, f})
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return fmt.Sprint(out[i].Labels) < fmt.Sprint(out[j].Labels) })
	if max > 0 && len(out) > max {
		out = out[:max]
	}
	return out, nil
}
