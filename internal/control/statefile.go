package control

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const DesiredStateOpenVSwitchExternalID = "netloom_desired_state"

func LoadDesiredStateJSON(r io.Reader) (DesiredState, error) {
	var state DesiredState
	decoder := json.NewDecoder(r)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return DesiredState{}, fmt.Errorf("decode desired state: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return DesiredState{}, fmt.Errorf("decode desired state: multiple JSON documents")
	}
	return state, nil
}

func MarshalDesiredStateJSON(state DesiredState) ([]byte, error) {
	return json.Marshal(state)
}
