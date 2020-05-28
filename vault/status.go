package vault

import "log"

type StatusCode int

const (
	// Vault heath statuses
	StatusUnknown StatusCode = iota
	StatusActive
	StatusStandBy
	StatusNotInit
	StatusSealed
)

func (v *vault) Status() (StatusCode, error) {
	req := v.client.NewRequest("GET", "/v1/sys/health")

	res, err := v.client.Do(req)
	if err != nil {
		return StatusUnknown, err
	}
	defer res.Body.Close()

	return getStatusCode(res.StatusCode), nil
}

func getStatusCode(statusCode int) StatusCode {
	sm := map[int]StatusCode{
		200: StatusActive,
		429: StatusStandBy,
		501: StatusNotInit,
		503: StatusSealed,
	}

	if val, ok := sm[statusCode]; ok {
		return val
	}

	log.Printf("Unknown status code: %v", statusCode)

	return StatusUnknown
}

func (sc StatusCode) String() string {
	return [...]string{"Unknown", "Active", "StandBy", "Not Initialized", "Sealed"}[sc]
}
