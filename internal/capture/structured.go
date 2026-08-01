package capture

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/textproto"
	"sort"
	"strconv"
	"strings"
)

func ParseStructured(contentType string, body []byte, l Limits) ([]StructuredField, []string) {
	if int64(len(body)) > l.MaxBodyBytes {
		return nil, []string{"structured body exceeds limit"}
	}
	mt, p, err := mime.ParseMediaType(contentType)
	if err != nil && contentType != "" {
		return nil, []string{"malformed content type"}
	}
	switch {
	case strings.Contains(mt, "xml") || bytes.HasPrefix(bytes.TrimSpace(body), []byte("<")):
		return parseXML(body, l)
	case strings.Contains(mt, "json") || bytes.HasPrefix(bytes.TrimSpace(body), []byte("{")) || bytes.HasPrefix(bytes.TrimSpace(body), []byte("[")):
		return parseJSON(body, l)
	case strings.HasPrefix(mt, "multipart/"):
		return parseMultipart(body, p["boundary"], l, 0)
	default:
		return nil, nil
	}
}
func sf(path, kind, value string) StructuredField {
	preview := redactedPreview(value)
	return StructuredField{Path: path, Kind: kind, ValueType: valueClass(value), Fingerprint: fingerprint([]byte(value)), Preview: preview, State: "present_redacted", Length: len(value), Repetition: 1, Confidence: "high"}
}
func redactedPreview(v string) string {
	if v == "" {
		return ""
	}
	return fmt.Sprintf("<redacted:%d:%s>", len(v), fingerprint([]byte(v))[:12])
}
func valueClass(v string) string {
	if v == "" {
		return "empty"
	}
	if _, e := strconv.ParseInt(v, 10, 64); e == nil {
		return "integer"
	}
	if _, e := strconv.ParseFloat(v, 64); e == nil {
		return "number"
	}
	if v == "true" || v == "false" || v == "null" {
		return v
	}
	return "string"
}

func parseXML(body []byte, l Limits) ([]StructuredField, []string) {
	if bytes.Contains(bytes.ToUpper(body), []byte("<!DOCTYPE")) || bytes.Contains(bytes.ToUpper(body), []byte("<!ENTITY")) {
		return nil, []string{"XML DTD or entity declaration rejected"}
	}
	d := xml.NewDecoder(bytes.NewReader(body))
	d.Strict = true
	var out []StructuredField
	var stack []xml.Name
	counts := map[string]int{}
	elements, attrs := 0, 0
	for {
		tok, e := d.Token()
		if e == io.EOF {
			break
		}
		if e != nil {
			return out, []string{"malformed XML"}
		}
		switch x := tok.(type) {
		case xml.StartElement:
			elements++
			if elements > l.MaxFields {
				return out, []string{"XML element limit exceeded"}
			}
			if len(stack) >= l.MaxXMLDepth {
				return out, []string{"XML depth limit exceeded"}
			}
			stack = append(stack, x.Name)
			path := xmlPath(stack)
			counts[path]++
			f := sf(path, "element", x.Name.Local)
			f.Namespace = x.Name.Space
			f.LocalName = x.Name.Local
			f.Repetition = counts[path]
			out = append(out, f)
			attrs += len(x.Attr)
			if attrs > l.MaxFields {
				return out, []string{"XML attribute limit exceeded"}
			}
			for _, a := range x.Attr {
				if len(a.Value) > l.MaxStringLength {
					return out, []string{"XML attribute value limit exceeded"}
				}
				af := sf(path+"/@"+a.Name.Local, "attribute", a.Value)
				af.Namespace = a.Name.Space
				af.LocalName = a.Name.Local
				out = append(out, af)
			}
		case xml.CharData:
			v := strings.TrimSpace(string(x))
			if v != "" {
				if len(v) > l.MaxStringLength {
					return out, []string{"XML text limit exceeded"}
				}
				out = append(out, sf(xmlPath(stack)+"/#text", "text", v))
			}
		case xml.EndElement:
			if len(stack) == 0 {
				return out, []string{"XML nesting conflict"}
			}
			stack = stack[:len(stack)-1]
		}
	}
	sortFields(out)
	return out, nil
}
func xmlPath(s []xml.Name) string {
	var b strings.Builder
	for _, n := range s {
		b.WriteByte('/')
		if n.Space != "" {
			b.WriteString("{")
			b.WriteString(n.Space)
			b.WriteString("}")
		}
		b.WriteString(n.Local)
	}
	return b.String()
}

func parseJSON(body []byte, l Limits) ([]StructuredField, []string) {
	d := json.NewDecoder(bytes.NewReader(body))
	d.UseNumber()
	var out []StructuredField
	var parse func(string, int) error
	parse = func(path string, depth int) error {
		if depth > l.MaxJSONDepth {
			return errors.New("JSON depth limit exceeded")
		}
		tok, e := d.Token()
		if e != nil {
			return e
		}
		switch v := tok.(type) {
		case json.Delim:
			switch v {
			case '{':
				seen := map[string]bool{}
				n := 0
				for d.More() {
					kt, e := d.Token()
					if e != nil {
						return e
					}
					k := kt.(string)
					n++
					if n > l.MaxFields {
						return errors.New("JSON object member limit exceeded")
					}
					if seen[k] {
						return fmt.Errorf("duplicate JSON key at %s/%s", path, k)
					}
					seen[k] = true
					if e = parse(path+"/"+escapePath(k), depth+1); e != nil {
						return e
					}
				}
				_, e = d.Token()
				return e
			case '[':
				n := 0
				for d.More() {
					if n >= l.MaxFields {
						return errors.New("JSON array member limit exceeded")
					}
					if e = parse(fmt.Sprintf("%s/%d", path, n), depth+1); e != nil {
						return e
					}
					n++
				}
				_, e = d.Token()
				return e
			}
		case string:
			if len(v) > l.MaxStringLength {
				return errors.New("JSON string limit exceeded")
			}
			out = append(out, sf(path, "json_value", v))
		case json.Number:
			out = append(out, sf(path, "json_value", v.String()))
		case bool:
			out = append(out, sf(path, "json_value", strconv.FormatBool(v)))
		case nil:
			out = append(out, sf(path, "json_value", "null"))
		}
		return nil
	}
	if e := parse("$", 0); e != nil {
		return out, []string{e.Error()}
	}
	if d.More() {
		return out, []string{"JSON trailing data"}
	}
	var extra any
	if e := d.Decode(&extra); e != io.EOF {
		return out, []string{"JSON trailing garbage"}
	}
	sortFields(out)
	return out, nil
}
func escapePath(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "~", "~0"), "/", "~1")
}

func parseMultipart(body []byte, boundary string, l Limits, depth int) ([]StructuredField, []string) {
	if boundary == "" {
		return nil, []string{"multipart boundary missing"}
	}
	if depth > 2 {
		return nil, []string{"multipart nesting limit exceeded"}
	}
	r := multipart.NewReader(bytes.NewReader(body), boundary)
	var out []StructuredField
	for i := 0; i < l.MaxMultipartMembers; i++ {
		p, e := r.NextPart()
		if e == io.EOF {
			sortFields(out)
			return out, nil
		}
		if e != nil {
			return out, []string{"malformed multipart framing"}
		}
		data, e := io.ReadAll(io.LimitReader(p, l.MaxBodyBytes+1))
		_ = p.Close()
		if e != nil || int64(len(data)) > l.MaxBodyBytes {
			return out, []string{"multipart part limit exceeded"}
		}
		base := fmt.Sprintf("/part/%d", i)
		out = append(out, sf(base+"/content-disposition", "metadata", redactDisposition(p.Header)))
		ct := p.Header.Get("Content-Type")
		out = append(out, sf(base+"/content-type", "metadata", ct))
		mt, params, _ := mime.ParseMediaType(ct)
		if strings.HasPrefix(mt, "multipart/") {
			nested, w := parseMultipart(data, params["boundary"], l, depth+1)
			for j := range nested {
				nested[j].Path = base + nested[j].Path
			}
			out = append(out, nested...)
			if len(w) > 0 {
				return out, w
			}
		} else {
			nested, w := ParseStructured(ct, data, l)
			if len(nested) > 0 {
				for j := range nested {
					nested[j].Path = base + nested[j].Path
				}
				out = append(out, nested...)
			} else {
				out = append(out, sf(base+"/body", "opaque", fingerprint(data)))
			}
			if len(w) > 0 {
				return out, w
			}
		}
	}
	return out, []string{"multipart part count limit exceeded"}
}
func redactDisposition(h textproto.MIMEHeader) string {
	v := h.Get("Content-Disposition")
	mt, p, e := mime.ParseMediaType(v)
	if e != nil {
		return "malformed"
	}
	if _, ok := p["filename"]; ok {
		p["filename"] = "<redacted>"
	}
	keys := make([]string, 0, len(p))
	for k := range p {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString(mt)
	for _, k := range keys {
		b.WriteString(";")
		b.WriteString(k)
		b.WriteString("=")
		b.WriteString(p[k])
	}
	return b.String()
}
func sortFields(x []StructuredField) {
	sort.Slice(x, func(i, j int) bool {
		if x[i].Path != x[j].Path {
			return x[i].Path < x[j].Path
		}
		return x[i].Kind < x[j].Kind
	})
}
