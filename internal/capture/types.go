// Package capture implements bounded, offline-only capture normalization and research.
package capture

import "time"

const SchemaVersion = 1
const AlgorithmVersion = "capture-analysis-v1"

type Limits struct {
	MaxCaptureBytes, MaxStreamBytes, MaxBodyBytes, MaxDecompressedBytes     int64
	MaxPackets, MaxStreams, MaxFields, MaxMultipartMembers, MaxObservations int
	MaxXMLDepth, MaxJSONDepth, MaxStringLength                              int
	MaxCompressionRatio                                                     float64
}

func DefaultLimits() Limits {
	return Limits{32 << 20, 4 << 20, 2 << 20, 8 << 20, 250000, 2048, 512, 64, 4096, 32, 32, 4096, 64}
}

type ValueState string

const (
	Absent      ValueState = "absent"
	Empty       ValueState = "present_empty"
	Redacted    ValueState = "present_redacted"
	Parsed      ValueState = "present_parsed"
	Malformed   ValueState = "present_malformed"
	Unsupported ValueState = "present_unsupported"
	Truncated   ValueState = "truncated"
	Unknown     ValueState = "unknown"
)

type Field struct {
	State       ValueState `json:"state"`
	Fingerprint string     `json:"fingerprint,omitempty"`
	Length      int64      `json:"length,omitempty"`
}
type Header struct {
	Name  string `json:"name"`
	Value Field  `json:"value"`
}
type Endpoint struct {
	AddressFingerprint string `json:"address_fingerprint,omitempty"`
	Port               uint16 `json:"port,omitempty"`
}
type Message struct {
	ID, Direction, Method, Route, HTTPVersion    string
	StatusCode                                   int
	MediaType, ContentEncoding, TransferEncoding string
	QueryKeys                                    []string
	Headers                                      []Header
	DeclaredLength                               int64
	Body                                         Field
	RawMemberFingerprint                         string
	Warnings                                     []string
	Structured                                   []StructuredField `json:"structured,omitempty"`
	rawBody                                      []byte
}
type Interface struct {
	ID                  int    `json:"id"`
	LinkType            uint16 `json:"link_type"`
	SnapLength          uint32 `json:"snap_length"`
	TimestampResolution uint64 `json:"timestamp_resolution"`
	CommentFingerprint  string `json:"comment_fingerprint,omitempty"`
	Supported           bool   `json:"supported"`
}
type Packet struct {
	ID             string    `json:"id"`
	Index          int       `json:"index"`
	InterfaceID    int       `json:"interface_id"`
	Timestamp      time.Time `json:"timestamp,omitempty"`
	CapturedLength uint32    `json:"captured_length"`
	OriginalLength uint32    `json:"original_length"`
	Truncated      bool      `json:"truncated"`
	LinkType       uint16    `json:"link_type"`
	Fingerprint    string    `json:"fingerprint"`
	Warning        string    `json:"warning,omitempty"`
}
type Flow struct {
	ID                  string   `json:"id"`
	Client              Endpoint `json:"client"`
	Server              Endpoint `json:"server"`
	Transport           string   `json:"transport"`
	State               string   `json:"state"`
	PacketIDs           []string `json:"packet_ids"`
	RequestCount        int      `json:"request_count"`
	ResponseCount       int      `json:"response_count"`
	Gaps                int      `json:"gaps"`
	Duplicates          int      `json:"duplicates"`
	Retransmissions     int      `json:"retransmissions"`
	Conflicts           int      `json:"conflicts"`
	DirectionConfidence string   `json:"direction_confidence"`
	Warnings            []string `json:"warnings,omitempty"`
}
type StructuredField struct {
	Path        string `json:"path"`
	Kind        string `json:"kind"`
	Namespace   string `json:"namespace,omitempty"`
	LocalName   string `json:"local_name,omitempty"`
	ValueType   string `json:"value_type"`
	Fingerprint string `json:"fingerprint"`
	Preview     string `json:"preview"`
	State       string `json:"state"`
	Length      int    `json:"length"`
	Repetition  int    `json:"repetition"`
	Confidence  string `json:"confidence"`
}
type Exchange struct {
	ID, StreamID          string
	Index                 int
	Request, Response     *Message
	AssociationEvidence   []string
	AssociationConfidence string
	Ambiguities           []string
	ResponseComplete      bool
	StartedAt             time.Time
	State                 string `json:"state"`
}
type SequenceEdge struct {
	From, To, Kind, Evidence, Confidence string
	DeltaNanos                           int64
	Coverage                             int      `json:"coverage"`
	Counterexamples                      []string `json:"counterexamples,omitempty"`
	SourceFixtures                       []string `json:"source_fixtures,omitempty"`
}
type Sequence struct {
	ID, Classification string
	ExchangeIDs        []string
	Edges              []SequenceEdge
	Warnings           []string
}
type Observation struct {
	ID, MessageID, Kind, Representation, Evidence, Confidence, Interpretation string
	Offset, Length                                                            int
	Structural                                                                bool
	SourceCaptureIDs, Counterexamples                                         []string
}
type Source struct {
	ID, Format, Fingerprint, SignatureState, Provenance string
	StartedAt, EndedAt                                  time.Time
	Labels                                              map[string]string
	Warnings                                            []string
}
type NormalizedCapture struct {
	SchemaVersion    int            `json:"schema_version"`
	AlgorithmVersion string         `json:"algorithm_version"`
	Source           Source         `json:"source"`
	Exchanges        []Exchange     `json:"exchanges"`
	Sequence         Sequence       `json:"sequence"`
	Observations     []Observation  `json:"observations"`
	RedactionSummary map[string]int `json:"redaction_summary"`
	Interfaces       []Interface    `json:"interfaces,omitempty"`
	Packets          []Packet       `json:"packets,omitempty"`
	Flows            []Flow         `json:"flows,omitempty"`
}
type MatrixMember struct {
	Label, CapturePath, Fingerprint string
	Variables                       map[string]string
}
type Matrix struct {
	SchemaVersion int            `json:"schema_version" yaml:"schema_version"`
	Name          string         `json:"name" yaml:"name"`
	Controlled    []string       `json:"controlled" yaml:"controlled"`
	Fixed         []string       `json:"fixed" yaml:"fixed"`
	Members       []MatrixMember `json:"members" yaml:"members"`
}
type MatrixResult struct {
	Quality                                        string `json:"quality"`
	SampleCount                                    int    `json:"sample_count"`
	Limitations, Confounders, Duplicates, Warnings []string
	MissingCells                                   []string `json:"missing_cells,omitempty"`
	Recommendations                                []string `json:"recommendations,omitempty"`
	Completeness                                   float64  `json:"completeness"`
	Confidence                                     string   `json:"confidence"`
}
type ParserCandidate struct {
	ID, Fingerprint, State, AlgorithmVersion                                          string
	Constraints, Preconditions, ConstantRegions, VariableRegions, Unknowns, Conflicts []string
	SampleCoverage                                                                    int
	PositiveExamples, NegativeExamples, Counterexamples                               []string
	LiveExecution                                                                     bool
	InputContentType                                                                  string   `json:"input_content_type,omitempty"`
	RootStructure                                                                     string   `json:"root_structure,omitempty"`
	ParserVersion                                                                     string   `json:"parser_version,omitempty"`
	RequiredFields                                                                    []string `json:"required_fields,omitempty"`
	OptionalFields                                                                    []string `json:"optional_fields,omitempty"`
	VariableFields                                                                    []string `json:"variable_fields,omitempty"`
	FailureExamples                                                                   []string `json:"failure_examples,omitempty"`
	CorpusCoverage                                                                    int      `json:"corpus_coverage"`
}
type Analysis struct {
	Capture                     NormalizedCapture `json:"capture"`
	Matrix                      *MatrixResult     `json:"matrix,omitempty"`
	Candidates                  []ParserCandidate `json:"parser_candidates"`
	Fingerprint                 string            `json:"fingerprint"`
	LivePolicyCollectionBlocked bool              `json:"live_policy_collection_blocked"`
	Findings                    []ResearchFinding `json:"findings"`
	Capabilities                []string          `json:"capabilities"`
}
type ResearchFinding struct {
	ID, State, Description string
	Vulnerability          bool
}
