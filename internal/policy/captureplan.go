package policy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type CapturePlanOptions struct {
	Output, SiteCode, ManagementPoint, ClientIDReference string
	Force                                                bool
}

func CreateCapturePlan(o CapturePlanOptions) error {
	if o.Output == "" || filepath.Clean(o.Output) == "." {
		return errors.New("capture-plan output is required")
	}
	if _, e := os.Lstat(o.Output); e == nil && !o.Force {
		return errors.New("capture-plan output already exists")
	}
	parent := filepath.Dir(o.Output)
	if e := os.MkdirAll(parent, 0700); e != nil {
		return e
	}
	tmp, e := os.MkdirTemp(parent, ".capture-plan-*")
	if e != nil {
		return e
	}
	ok := false
	defer func() {
		if !ok {
			_ = os.RemoveAll(tmp)
		}
	}()
	values := map[string]string{"README.txt": "Authorized isolated-lab preparation only. CinderPath does not capture traffic, retrieve policy, register clients, or contact a management point. Never commit raw captures.\n", "metadata.template.yaml": fmt.Sprintf("name: authorized-lab-placeholder\nsynthetic: false\nsanitized: false\nsite_code: %q\nmanagement_point_reference: %q\nclient_id_reference: %q\nsanitization_sentinel: CINDERPATH_SYNTHETIC_SANITIZER_SENTINEL\n", o.SiteCode, o.ManagementPoint, o.ClientIDReference), "replacements.template.yaml": "REALDOMAIN: DOMAIN_0001\nsccm01.example.invalid: HOST_MP_000000000000\n", "review-checklist.txt": "Confirm authorization.\nKeep raw captures encrypted and outside source control.\nInspect every opaque body.\nScan for credentials, tokens, cookies, certificates, keys, identifiers, and sentinels.\n", "commands-linux.txt": captureCommands(), "commands-windows.txt": captureCommands(), "expected-layout.txt": "raw-example/metadata.yaml\nraw-example/request.headers\nraw-example/request.body\nraw-example/response.headers\nraw-example/response.body\n", ".gitignore": "raw*/\n*.pcap\n*.pcapng\n*.etl\n*secrets*\n*.key\n*.pem\nreplacements*.yaml\nrequest.body\nresponse.body\n"}
	for n, b := range values {
		if e = atomicWrite(filepath.Join(tmp, n), []byte(b), 0600, false); e != nil {
			return e
		}
	}
	_ = os.Chmod(tmp, 0700)
	if o.Force {
		if st, e := os.Lstat(o.Output); e == nil {
			if !st.IsDir() {
				return errors.New("capture-plan output is not a directory")
			}
			backup := o.Output + ".previous"
			if _, e = os.Lstat(backup); e == nil {
				return errors.New("capture-plan backup already exists")
			}
			if e = os.Rename(o.Output, backup); e != nil {
				return e
			}
			if e = os.Rename(tmp, o.Output); e != nil {
				_ = os.Rename(backup, o.Output)
				return e
			}
			_ = os.RemoveAll(backup)
			ok = true
			return nil
		}
	}
	if e = os.Rename(tmp, o.Output); e != nil {
		return e
	}
	ok = true
	return nil
}
func captureCommands() string {
	return `# Replace placeholders with authorized local paths and IDs.
cinderpath protocol sanitize --input captures/raw-example --output captures/metadata-example --binary-mode metadata_only
cinderpath protocol inspect-binary captures/raw-example/request.body
cinderpath protocol sanitize --input captures/raw-example --output captures/text-example --binary-mode text_regions --replacement-map replacements.yaml
cinderpath protocol import --directory captures/text-example
cinderpath protocol serve-fixtures --directory captures/text-example --listen 127.0.0.1:0 --strict --once
cinderpath protocol replay CONTRACT_ID --directory captures/text-example --endpoint http://127.0.0.1:PORT
cinderpath protocol bundle inspect --input sanitized-policy-bundle.tar.gz
cinderpath protocol bundle export --contract CONTRACT_ID --directory captures/text-example --output sanitized-policy-bundle.tar.gz
`
}
