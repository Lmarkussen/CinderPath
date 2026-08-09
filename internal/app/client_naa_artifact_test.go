package app

import (
	"context"
	"testing"
	"time"

	"github.com/Lmarkussen/CinderPath/internal/policy"
)

func TestClientNAAArtifactPersistenceIsMetadataOnly(t *testing.T) {
	a := clientIdentityApplication(t)
	x, err := policy.ParseClientNAAArtifact([]byte(`kind: sccm_client_naa_artifact
source_host: CLIENT
domain: SCCM.LAB
site_code: P01
namespace: root\ccm\policy\machine\actualconfig
class: CCM_NetworkAccessAccount
captured_at: "2099-01-01T00:00:00Z"
source: {type: local_sccm_client_artifact, verified: true}
network_access_username: {present: true, material_state: protected, length: 585}
network_access_password: {present: true, material_state: protected, length: 585}
`))
	if err != nil {
		t.Fatal(err)
	}
	if err = a.ImportClientNAAArtifact(context.Background(), x); err != nil {
		t.Fatal(err)
	}
	got, err := a.StoredClientNAAArtifact(context.Background(), "sccm.lab", time.Hour*24*365*100)
	if err != nil || !got.Artifact.Password.Present || got.Artifact.Password.Length != 585 {
		t.Fatalf("%+v %v", got, err)
	}
}
