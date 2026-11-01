package evidence

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const maxResponseBytes = 4 << 20

// HTTPQuerier evaluates instant queries against the Prometheus HTTP API or the
// Loki query API. Both return the same vector/scalar envelope for metric queries.
type HTTPQuerier struct {
	backend  Backend
	endpoint string
	token    string
	client   *http.Client
}

// NewPrometheus returns nil when baseURL is empty so callers can pass the result
// straight to NewCollector.
func NewPrometheus(baseURL, bearerToken string, client *http.Client) Querier {
	return newHTTPQuerier(Prometheus, baseURL, "/api/v1/query", bearerToken, client)
}

func NewLoki(baseURL, bearerToken string, client *http.Client) Querier {
	return newHTTPQuerier(Loki, baseURL, "/loki/api/v1/query", bearerToken, client)
}

func newHTTPQuerier(backend Backend, baseURL, path, token string, client *http.Client) Querier {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		return nil
	}
	if client == nil {
		client = &http.Client{}
	}
	return &HTTPQuerier{backend: backend, endpoint: baseURL + path, token: token, client: client}
}

func (q *HTTPQuerier) Instant(ctx context.Context, query string, at time.Time) (float64, bool, error) {
	params := url.Values{}
	params.Set("query", query)
	if q.backend == Loki {
		params.Set("time", strconv.FormatInt(at.UnixNano(), 10))
	} else {
		params.Set("time", strconv.FormatFloat(float64(at.UnixMilli())/1000, 'f', 3, 64))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, q.endpoint+"?"+params.Encode(), nil)
	if err != nil {
		return 0, false, err
	}
	req.Header.Set("Accept", "application/json")
	if q.token != "" {
		req.Header.Set("Authorization", "Bearer "+q.token)
	}
	resp, err := q.client.Do(req)
	if err != nil {
		return 0, false, fmt.Errorf("%s query failed: %w", q.backend, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return 0, false, fmt.Errorf("%s response read failed: %w", q.backend, err)
	}
	if len(body) > maxResponseBytes {
		return 0, false, fmt.Errorf("%s response exceeded %d bytes", q.backend, maxResponseBytes)
	}
	return parseInstant(q.backend, resp.StatusCode, body)
}

type apiEnvelope struct {
	Status    string `json:"status"`
	ErrorType string `json:"errorType"`
	Error     string `json:"error"`
	Data      struct {
		ResultType string          `json:"resultType"`
		Result     json.RawMessage `json:"result"`
	} `json:"data"`
}

func parseInstant(backend Backend, statusCode int, body []byte) (float64, bool, error) {
	var envelope apiEnvelope
	decodeErr := json.Unmarshal(body, &envelope)
	if statusCode != http.StatusOK {
		if decodeErr == nil && envelope.Error != "" {
			return 0, false, fmt.Errorf("%s returned HTTP %d: %s", backend, statusCode, envelope.Error)
		}
		return 0, false, fmt.Errorf("%s returned HTTP %d", backend, statusCode)
	}
	if decodeErr != nil {
		return 0, false, fmt.Errorf("%s returned invalid JSON: %w", backend, decodeErr)
	}
	if envelope.Status != "success" {
		return 0, false, fmt.Errorf("%s query status %q: %s", backend, envelope.Status, envelope.Error)
	}

	switch envelope.Data.ResultType {
	case "vector":
		var series []struct {
			Value [2]json.RawMessage `json:"value"`
		}
		if err := json.Unmarshal(envelope.Data.Result, &series); err != nil {
			return 0, false, fmt.Errorf("%s returned an invalid vector: %w", backend, err)
		}
		best, found := math.Inf(-1), false
		for _, item := range series {
			value, err := sampleValue(item.Value[1])
			if err != nil {
				return 0, false, fmt.Errorf("%s returned an invalid sample: %w", backend, err)
			}
			if math.IsNaN(value) {
				continue
			}
			if !found || value > best {
				best, found = value, true
			}
		}
		if !found {
			return 0, false, nil
		}
		return best, true, nil
	case "scalar":
		var sample [2]json.RawMessage
		if err := json.Unmarshal(envelope.Data.Result, &sample); err != nil {
			return 0, false, fmt.Errorf("%s returned an invalid scalar: %w", backend, err)
		}
		value, err := sampleValue(sample[1])
		if err != nil {
			return 0, false, fmt.Errorf("%s returned an invalid scalar: %w", backend, err)
		}
		if math.IsNaN(value) {
			return 0, false, nil
		}
		return value, true, nil
	default:
		return 0, false, fmt.Errorf("%s returned result type %q; probes must aggregate to a vector or scalar", backend, envelope.Data.ResultType)
	}
}

func sampleValue(raw json.RawMessage) (float64, error) {
	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		return 0, err
	}
	return strconv.ParseFloat(text, 64)
}
