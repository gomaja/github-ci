package acceptance

import (
	"bytes"
	"testing"
)

func FuzzDecodeAcceptanceRecord(f *testing.F) {
	valid, err := MarshalRecord(validAcceptanceRecord())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte("{}"))
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = DecodeRecord(bytes.NewReader(data), testCandidateSHA)
	})
}

func FuzzStrictGitHubObject(f *testing.F) {
	f.Add([]byte(`{"full_name":"acme/go-canary","private":false,"visibility":"public"}`))
	f.Add([]byte(`{"full_name":"first","full_name":"second"}`))
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = strictObject(data, repositoryFields)
	})
}
