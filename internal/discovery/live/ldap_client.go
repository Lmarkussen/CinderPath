package live

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
)

var rootDSEAttributes = []string{"defaultNamingContext", "configurationNamingContext", "rootDomainNamingContext", "schemaNamingContext", "dnsHostName", "supportedLDAPVersion", "supportedSASLMechanisms", "domainFunctionality", "forestFunctionality", "domainControllerFunctionality", "isGlobalCatalogReady"}
var sccmAttributes = []string{"objectClass", "cn", "distinguishedName", "dNSHostName", "name", "keywords", "serviceBindingInformation", "serviceClassName"}

type rootDSE struct {
	DefaultNamingContext, ConfigurationNamingContext, RootDomainNamingContext, SchemaNamingContext, DNSHostName string
	SupportedLDAPVersion, SupportedSASLMechanisms                                                               []string
	DomainFunctionality, ForestFunctionality, DomainControllerFunctionality, IsGlobalCatalogReady               string
}
type directoryObject struct {
	DN         string              `json:"distinguished_name"`
	Attributes map[string][]string `json:"attributes"`
	Roles      []string            `json:"roles,omitempty"`
	Hosts      []string            `json:"hosts,omitempty"`
}
type directoryClient interface {
	RootDSE(context.Context) (rootDSE, error)
	SearchSCCM(context.Context, rootDSE, string, int, int) ([]directoryObject, error)
	Close() error
}
type goLDAPClient struct {
	conn *ldap.Conn
	opts LDAPOptions
}

func connectLDAP(ctx context.Context, opts LDAPOptions) (directoryClient, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	scheme := "ldap"
	if opts.UseTLS {
		scheme = "ldaps"
	}
	port := opts.Port
	if port == 0 {
		if opts.UseTLS {
			port = 636
		} else {
			port = 389
		}
	}
	host := strings.TrimSpace(opts.Server)
	if host == "" {
		return nil, fmt.Errorf("LDAP server is required")
	}
	u := url.URL{Scheme: scheme, Host: net.JoinHostPort(host, strconv.Itoa(port))}
	tlsCfg := opts.TLSConfig
	if tlsCfg == nil {
		tlsCfg = &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, InsecureSkipVerify: opts.InsecureSkipVerify}
	} // #nosec G402 -- explicit flag is recorded in evidence.
	operationTimeout := opts.SearchTimeout
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if operationTimeout <= 0 || remaining < operationTimeout {
			operationTimeout = remaining
		}
	}
	if operationTimeout <= 0 {
		return nil, context.DeadlineExceeded
	}
	opts.SearchTimeout = operationTimeout
	conn, err := ldap.DialURL(u.String(), ldap.DialWithDialer(&net.Dialer{Timeout: operationTimeout}), ldap.DialWithTLSConfig(tlsCfg))
	if err != nil {
		return nil, fmt.Errorf("connect LDAP endpoint: %w", err)
	}
	conn.SetTimeout(operationTimeout)
	if opts.StartTLS {
		if err := conn.StartTLS(tlsCfg); err != nil {
			conn.Close()
			return nil, fmt.Errorf("LDAP STARTTLS: %w", err)
		}
	}
	if opts.Anonymous {
		if err := conn.UnauthenticatedBind(""); err != nil {
			conn.Close()
			return nil, fmt.Errorf("explicit anonymous LDAP bind: %w", err)
		}
	} else {
		if opts.User == "" || opts.PasswordReference == "" {
			conn.Close()
			return nil, fmt.Errorf("LDAP credentials are required unless --ldap-anonymous is explicitly selected")
		}
		if err := conn.Bind(opts.User, opts.Password); err != nil {
			conn.Close()
			return nil, fmt.Errorf("LDAP bind for %q: %w", opts.User, err)
		}
	}
	return &goLDAPClient{conn: conn, opts: opts}, nil
}
func (c *goLDAPClient) Close() error { c.conn.Close(); return nil }
func (c *goLDAPClient) RootDSE(ctx context.Context) (rootDSE, error) {
	if err := ctx.Err(); err != nil {
		return rootDSE{}, err
	}
	req := ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, int(c.opts.SearchTimeout.Seconds()), false, "(objectClass=*)", rootDSEAttributes, nil)
	res, err := c.conn.Search(req)
	if err != nil {
		return rootDSE{}, err
	}
	if len(res.Entries) != 1 {
		return rootDSE{}, fmt.Errorf("RootDSE returned %d entries", len(res.Entries))
	}
	return parseRootDSE(entryAttributes(res.Entries[0])), nil
}
func (c *goLDAPClient) SearchSCCM(ctx context.Context, root rootDSE, baseOverride string, page, max int) ([]directoryObject, error) {
	bases := []string{baseOverride}
	if baseOverride == "" {
		bases = []string{root.DefaultNamingContext, root.ConfigurationNamingContext}
	}
	filters := []string{"(&(objectClass=serviceConnectionPoint)(|(keywords=*SMS*)(keywords=*SCCM*)(keywords=*ConfigMgr*)(serviceClassName=*SMS*)))", "(|(objectClass=mSSMSManagementPoint)(objectClass=mSSMSSite)(cn=System Management)(cn=*SCCM*)(cn=*SMS*))"}
	var out []directoryObject
	for _, base := range bases {
		if base == "" {
			continue
		}
		for _, filter := range filters {
			if err := ctx.Err(); err != nil {
				return out, err
			}
			remaining := max - len(out)
			if remaining <= 0 {
				return out, nil
			}
			req := ldap.NewSearchRequest(base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, remaining, int(c.opts.SearchTimeout.Seconds()), false, filter, sccmAttributes, nil)
			res, err := c.conn.SearchWithPaging(req, uint32(page))
			if err != nil {
				return out, fmt.Errorf("search %q: %w", base, err)
			}
			for _, entry := range res.Entries {
				out = append(out, parseDirectoryObject(entry.DN, entryAttributes(entry)))
				if len(out) >= max {
					return out, nil
				}
			}
		}
	}
	return out, nil
}
func entryAttributes(e *ldap.Entry) map[string][]string {
	out := map[string][]string{}
	for _, a := range e.Attributes {
		out[a.Name] = append([]string(nil), a.Values...)
	}
	return out
}
func getAttr(attrs map[string][]string, name string) []string {
	for key, v := range attrs {
		if strings.EqualFold(key, name) {
			return v
		}
	}
	return nil
}
func first(attrs map[string][]string, name string) string {
	v := getAttr(attrs, name)
	if len(v) > 0 {
		return v[0]
	}
	return ""
}
func parseRootDSE(a map[string][]string) rootDSE {
	return rootDSE{DefaultNamingContext: first(a, "defaultNamingContext"), ConfigurationNamingContext: first(a, "configurationNamingContext"), RootDomainNamingContext: first(a, "rootDomainNamingContext"), SchemaNamingContext: first(a, "schemaNamingContext"), DNSHostName: first(a, "dnsHostName"), SupportedLDAPVersion: getAttr(a, "supportedLDAPVersion"), SupportedSASLMechanisms: getAttr(a, "supportedSASLMechanisms"), DomainFunctionality: first(a, "domainFunctionality"), ForestFunctionality: first(a, "forestFunctionality"), DomainControllerFunctionality: first(a, "domainControllerFunctionality"), IsGlobalCatalogReady: first(a, "isGlobalCatalogReady")}
}
func parseDirectoryObject(dn string, a map[string][]string) directoryObject {
	o := directoryObject{DN: dn, Attributes: map[string][]string{}}
	for _, name := range sccmAttributes {
		if v := getAttr(a, name); len(v) > 0 {
			o.Attributes[name] = append([]string(nil), v...)
		}
	}
	text := strings.ToLower(dn + " " + strings.Join(flatten(o.Attributes), " "))
	switch {
	case strings.Contains(text, "mssmsmanagementpoint") || strings.Contains(text, "management point"):
		o.Roles = append(o.Roles, "management_point")
	case strings.Contains(text, "mssmssite") || strings.Contains(text, "site code"):
		o.Roles = append(o.Roles, "site_server")
	}
	for _, v := range append(getAttr(a, "dNSHostName"), getAttr(a, "serviceBindingInformation")...) {
		if h := hostFromValue(v); h != "" {
			o.Hosts = append(o.Hosts, h)
		}
	}
	o.Hosts = mergeUnique(o.Hosts)
	return o
}
func flatten(a map[string][]string) []string {
	var out []string
	for _, v := range a {
		out = append(out, v...)
	}
	return out
}
func hostFromValue(v string) string {
	v = strings.TrimSpace(v)
	if u, err := url.Parse(v); err == nil && u.Hostname() != "" {
		return strings.ToLower(u.Hostname())
	}
	if h, _, err := net.SplitHostPort(v); err == nil {
		return strings.ToLower(h)
	}
	if ip := net.ParseIP(v); ip != nil {
		return ip.String()
	}
	if strings.Contains(v, ".") && !strings.ContainsAny(v, " /,=") {
		return strings.ToLower(strings.TrimSuffix(v, "."))
	}
	return ""
}
func domainFromDN(dn string) string {
	var labels []string
	for _, part := range strings.Split(dn, ",") {
		part = strings.TrimSpace(part)
		if len(part) > 3 && strings.EqualFold(part[:3], "DC=") {
			labels = append(labels, part[3:])
		}
	}
	return strings.Join(labels, ".")
}

var _ = time.Second
