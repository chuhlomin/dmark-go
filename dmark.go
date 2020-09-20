package dmark

// Structures below help with parsing DMARK reports, that comply with DMARK XML Schema:
// https://tools.ietf.org/html/rfc7489#appendix-C

import (
	"fmt"
	"net"
	"strings"
)

// The time range in UTC covered by messages in this report, specified in seconds since epoch.
type DateRange struct {
	Begin int `xml:"begin" json:"begin"`
	Eng   int `xml:"end" json:"end"`
}

// Report generator metadata.
type ReportMetadata struct {
	OrgName          string    `xml:"org_name" json:"org_name"`
	Email            string    `xml:"email" json:"email"`
	ExtraContactInfo string    `xml:"extra_contact_info,omitempty" json:"extra_contact_info,omitempty"`
	ReportID         string    `xml:"report_id" json:"report_id"`
	DateRange        DateRange `xml:"date_range" json:"date_range"`
	Errors           []string  `xml:"error,omitempty" json:"error,omitempty"`
}

// Alignment mode (relaxed or strict) for DKIM and SPF.
type Alignment int

const (
	AlignmentRelaxed Alignment = iota
	AlignmentStrict
)

func (a Alignment) MarshalText() (text []byte, err error) {
	switch a {
	default:
		return []byte("unknown"), nil
	case AlignmentRelaxed:
		return []byte("relaxed"), nil
	case AlignmentStrict:
		return []byte("strict"), nil
	}
}

func (a *Alignment) UnmarshalText(text []byte) error {
	switch strings.ToLower(string(text)) {
	default:
		return fmt.Errorf("unexpected Alignment value %q", string(text))
	case "r":
		*a = AlignmentRelaxed
	case "s":
		*a = AlignmentStrict
	}

	return nil
}

// The policy actions specified by p and sp in the DMARC record.
type Disposition int

const (
	DispositionNone Disposition = iota
	DispositionQuarantine
	DispositionReject
)

func (disp Disposition) MarshalText() (text []byte, err error) {
	switch disp {
	default:
		return []byte("unknown"), nil
	case DispositionNone:
		return []byte("none"), nil
	case DispositionQuarantine:
		return []byte("quarantine"), nil
	case DispositionReject:
		return []byte("reject"), nil
	}
}

func (disp *Disposition) UnmarshalText(text []byte) error {
	switch strings.ToLower(string(text)) {
	default:
		return fmt.Errorf("unexpected Disposition value %q", string(text))
	case "none":
		*disp = DispositionNone
	case "quarantine":
		*disp = DispositionQuarantine
	case "reject":
		*disp = DispositionReject
	}

	return nil
}

// The DMARC policy that applied to the messages in this report.
type PolicyPublished struct {
	Domain string      `xml:"domain" json:"domain"`                   // The domain at which the DMARC record was found.
	ADKIM  Alignment   `xml:"adkim,omitempty" json:"adkim,omitempty"` // The DKIM alignment mode.
	ASPF   Alignment   `xml:"aspf,omitempty" json:"aspf,omitempty"`   // The SPF alignment mode.
	P      Disposition `xml:"p" json:"p"`                             // The policy to apply to messages from the domain.
	SP     Disposition `xml:"sp" json:"sp"`                           // The policy to apply to messages from subdomains.
	Pct    int         `xml:"pct" json:"pct"`                         // The percent of messages to which policy applies.
	Fo     string      `xml:"fo" json:"fo"`                           // Failure reporting options in effect.
}

// The DMARC-aligned authentication result.
// true - "pass", false – "fail"
type Result bool

func (r *Result) MarshalText() (text []byte, err error) {
	switch strings.ToLower(string(text)) {
	case "true":
		return []byte("true"), nil
	default:
		return []byte("false"), nil
	}
}

func (r *Result) UnmarshalText(text []byte) error {
	*r = strings.ToLower(string(text)) == "pass"

	return nil
}

// Reasons that may affect DMARC disposition or execution thereof.
type PolicyOverride int

const (
	// The message was relayed via a known forwarder, or local
	// heuristics identified the message as likely having been forwarded.
	// There is no expectation that authentication would pass.
	PolicyOverrideForwarded PolicyOverride = iota

	// The message was exempted from application of policy
	// by the "pct" setting in the DMARC policy record.
	PolicyOverrideSampledOut

	// Message authentication failure was anticipated by other evidence
	// linking the message to a locally maintained list of known and trusted forwarders.
	PolicyOverrideTrustedForwarder

	// Local heuristics determined that the message arrived via a mailing list,
	// and thus authentication of the original message was not expected to succeed.
	PolicyOverrideMailingList

	// The Mail Receiver's local policy exempted the message
	// from being subjected to the Domain Owner's requested policy action.
	PolicyOverrideLocalPolicy

	// Some policy exception not covered by the other entries in this list occurred.
	// Additional detail can be found in the PolicyOverrideReason's "comment" field.
	PolicyOverrideOther
)

func (po PolicyOverride) MarshalText() (text []byte, err error) {
	switch po {
	default:
		return []byte("unknown"), nil
	case PolicyOverrideForwarded:
		return []byte("forwarded"), nil
	case PolicyOverrideSampledOut:
		return []byte("sampled_out"), nil
	case PolicyOverrideTrustedForwarder:
		return []byte("trusted_forwarder"), nil
	case PolicyOverrideMailingList:
		return []byte("mailing_list"), nil
	case PolicyOverrideLocalPolicy:
		return []byte("local_policy"), nil
	case PolicyOverrideOther:
		return []byte("other"), nil
	}
}

func (po *PolicyOverride) UnmarshalText(text []byte) error {
	switch strings.ToLower(string(text)) {
	default:
		return fmt.Errorf("unexpected PolicyOverride value %q", string(text))
	case "forwarded":
		*po = PolicyOverrideForwarded
	case "sampled_out":
		*po = PolicyOverrideSampledOut
	case "trusted_forwarder":
		*po = PolicyOverrideTrustedForwarder
	case "mailing_list":
		*po = PolicyOverrideMailingList
	case "local_policy":
		*po = PolicyOverrideLocalPolicy
	case "other":
		*po = PolicyOverrideOther
	}

	return nil
}

// How do we allow report generators to include new classes of override reasons
// if they want to be more specific than "other"?
type PolicyOverrideReason struct {
	Type    PolicyOverride `xml:"type" json:"type"`
	Comment string         `xml:"comment,omitempty" json:"comment,omitempty"`
}

// Taking into account everything else in the record, the results of applying DMARC.
type PolicyEvaluated struct {
	Disposition Disposition            `xml:"disposition" json:"disposition"`
	DKIM        Result                 `xml:"dkim" json:"dkim"`
	SPF         Result                 `xml:"spf" json:"spf"`
	Reason      []PolicyOverrideReason `xml:"reason,omitempty" json:"reason,omitempty"`
}

type Row struct {
	SourceIP        net.IP          `xml:"source_ip" json:"source_ip"`               // The connecting IP
	Count           int             `xml:"count" json:"count"`                       // The number of matching messages
	PolicyEvaluated PolicyEvaluated `xml:"policy_evaluated" json:"policy_evaluated"` // The DMARC disposition applying to matching messages
}

type Identifiers struct {
	EnvelopeTo   string `xml:"envelope_to,omitempty" json:"envelope_to,omitempty"` // The envelope recipient domain
	EnvelopeFrom string `xml:"envelope_from" json:"envelope_from"`                 // The RFC5321.MailFrom domain
	HeaderFrom   string `xml:"header_from" json:"header_from"`                     // The RFC5322.From domain
}

// DKIM verification result, according to RFC 7001 Section 2.6.1.
type DKIMResult int

const (
	DKIMResultNone DKIMResult = iota
	DKIMResultPass
	DKIMResultFail
	DKIMResultPolicy
	DKIMResultNeutral
	DKIMResultTempError // "TempError" commonly implemented as "unknown"
	DKIMResultPermError // "PermError" commonly implemented as "error"
)

func (dkimr DKIMResult) MarshalText() (text []byte, err error) {
	switch dkimr {
	default:
		return []byte("unknown"), nil
	case DKIMResultNone:
		return []byte("none"), nil
	case DKIMResultPass:
		return []byte("pass"), nil
	case DKIMResultFail:
		return []byte("fail"), nil
	case DKIMResultPolicy:
		return []byte("policy"), nil
	case DKIMResultNeutral:
		return []byte("neutral"), nil
	case DKIMResultTempError:
		return []byte("temperror"), nil
	case DKIMResultPermError:
		return []byte("permerror"), nil
	}
}

func (dkimr *DKIMResult) UnmarshalText(text []byte) error {
	switch strings.ToLower(string(text)) {
	default:
		return fmt.Errorf("unexpected SPFResult value %q", string(text))
	case "none":
		*dkimr = DKIMResultNone
	case "pass":
		*dkimr = DKIMResultPass
	case "fail":
		*dkimr = DKIMResultFail
	case "policy":
		*dkimr = DKIMResultPolicy
	case "neutral":
		*dkimr = DKIMResultNeutral
	case "temperror":
		*dkimr = DKIMResultTempError
	case "permerror":
		*dkimr = DKIMResultPermError
	}

	return nil
}

type DKIMAuthResult struct {
	Domain      string     `xml:"domain" json:"domain"`                                 // The "d=" parameter in the signature
	Selector    string     `xml:"selector,omitempty" json:"selector,omitempty"`         // The "s=" parameter in the signature
	Result      DKIMResult `xml:"result" json:"result"`                                 // The DKIM verification result
	HumanResult string     `xml:"human_result,omitempty" json:"human_result,omitempty"` // Any extra information (e.g., from Authentication-Results)
}

// SPF domain scope
type SPFDomainScope int

const (
	SPFDomainScopeHelo  SPFDomainScope = iota
	SPFDomainScopeMFrom SPFDomainScope = iota
)

func (sds SPFDomainScope) MarshalText() (text []byte, err error) {
	switch sds {
	default:
		return []byte("unknown"), nil
	case SPFDomainScopeHelo:
		return []byte("helo"), nil
	case SPFDomainScopeMFrom:
		return []byte("mfrom"), nil
	}
}

func (sds *SPFDomainScope) UnmarshalText(text []byte) error {
	switch strings.ToLower(string(text)) {
	default:
		return fmt.Errorf("unexpected SPFDomainScope value %q", string(text))
	case "helo":
		*sds = SPFDomainScopeHelo
	case "mfrom":
		*sds = SPFDomainScopeMFrom
	}

	return nil
}

type SPFResult int

const (
	SPFResultNone SPFResult = iota
	SPFResultNeutral
	SPFResultPass
	SPFResultFail
	SPFResultSoftFail
	SPFResultTempError // "TempError" commonly implemented as "unknown"
	SPFResultPermError // "PermError" commonly implemented as "error"
)

func (spfr SPFResult) MarshalText() (text []byte, err error) {
	switch spfr {
	default:
		return []byte("unknown"), nil
	case SPFResultNone:
		return []byte("none"), nil
	case SPFResultNeutral:
		return []byte("neutral"), nil
	case SPFResultPass:
		return []byte("pass"), nil
	case SPFResultFail:
		return []byte("fail"), nil
	case SPFResultSoftFail:
		return []byte("softfail"), nil
	case SPFResultTempError:
		return []byte("temperror"), nil
	case SPFResultPermError:
		return []byte("permerror"), nil
	}
}

func (spfr *SPFResult) UnmarshalText(text []byte) error {
	switch strings.ToLower(string(text)) {
	default:
		return fmt.Errorf("unexpected SPFResult value %q", string(text))
	case "none":
		*spfr = SPFResultNone
	case "neutral":
		*spfr = SPFResultNeutral
	case "pass":
		*spfr = SPFResultPass
	case "fail":
		*spfr = SPFResultFail
	case "softfail":
		*spfr = SPFResultSoftFail
	case "temperror":
		*spfr = SPFResultTempError
	case "permerror":
		*spfr = SPFResultPermError
	}

	return nil
}

type SPFAuthResult struct {
	Domain string         `xml:"domain" json:"domain"` // The checked domain
	Scope  SPFDomainScope `xml:"scope" json:"scope"`   // The scope of the checked domain
	Result SPFResult      `xml:"result" json:"result"` // The SPF verification result
}

// This element contains DKIM and SPF results, uninterpreted with respect to DMARC
type AuthResult struct {
	DKIM []DKIMAuthResult `xml:"dkim" json:"dkim"` // There may be no DKIM signatures, or multiple DKIM signatures
	SPF  []SPFAuthResult  `xml:"spf" json:"spf"`   // There will always be at least one SPF result
}

// This element contains all the authentication results that were evaluated
// by the receiving system for the given set of messages
type Record struct {
	Row         Row         `xml:"row" json:"row"`
	Identifiers Identifiers `xml:"identifiers" json:"identifiers"`
	AuthResult  AuthResult  `xml:"auth_results" json:"auth_results"`
}

// Parent
type Feedback struct {
	Version         int             `xml:"version,omitempty" json:"version,omitempty"` // The "version" for reports generated per this specification MUST be the value 1.0.
	ReportMetadata  ReportMetadata  `xml:"report_metadata" json:"report_metadata"`
	PolicyPublished PolicyPublished `xml:"policy_published" json:"policy_published"`
	Record          []Record        `xml:"record" json:"record"`
}
