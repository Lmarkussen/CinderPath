//go:build integration

package live

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestConfiguredLDAPIntegration(t *testing.T) {
	server := os.Getenv("CINDERPATH_TEST_LDAP_SERVER")
	user := os.Getenv("CINDERPATH_TEST_LDAP_USER")
	password := os.Getenv("CINDERPATH_TEST_LDAP_PASSWORD")
	if server == "" || user == "" || password == "" {
		t.Skip("CINDERPATH_TEST_LDAP_SERVER, USER, and PASSWORD are required")
	}
	client, err := connectLDAP(context.Background(), LDAPOptions{Enabled: true, Server: server, User: user, Password: password, PasswordReference: "env:CINDERPATH_TEST_LDAP_PASSWORD", SearchTimeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.RootDSE(context.Background()); err != nil {
		t.Fatal(err)
	}
}
