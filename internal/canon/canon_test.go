package canon

import (
	"encoding/json"
	"testing"
)

type canonCase struct {
	name      string
	strategy  string
	before    any
	after     any
	opts      map[string]any
	wantEqual bool
	wantNote  bool
}

func runCases(t *testing.T, cases []canonCase) {
	t.Helper()
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			f, err := Lookup(tc.strategy)
			if err != nil {
				t.Fatalf("Lookup(%q): %v", tc.strategy, err)
			}
			res := f(tc.before, tc.after, tc.opts)
			if res.Equal != tc.wantEqual {
				t.Errorf("Equal = %v, want %v\n  before: %v\n  after:  %v\n  detail: %s",
					res.Equal, tc.wantEqual, tc.before, tc.after, res.Detail)
			}
			if tc.wantNote && res.Note == "" {
				t.Errorf("expected an advisory Note, got none")
			}
		})
	}
}

func TestAWSPolicyJSON(t *testing.T) {
	runCases(t, []canonCase{
		{
			name:     "key order and whitespace only",
			strategy: "aws_policy_json",
			before:   `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}]}`,
			after: `{
  "Statement": [
    {
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::b/*",
      "Effect": "Allow"
    }
  ],
  "Version": "2012-10-17"
}`,
			wantEqual: true,
		},
		{
			name:      "statement order swapped",
			strategy:  "aws_policy_json",
			before:    `{"Version":"2012-10-17","Statement":[{"Sid":"A","Effect":"Allow","Action":"s3:GetObject","Resource":"*"},{"Sid":"B","Effect":"Allow","Action":"s3:PutObject","Resource":"*"}]}`,
			after:     `{"Version":"2012-10-17","Statement":[{"Sid":"B","Effect":"Allow","Action":"s3:PutObject","Resource":"*"},{"Sid":"A","Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`,
			wantEqual: true,
		},
		{
			name:      "scalar action vs single-element array",
			strategy:  "aws_policy_json",
			before:    `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`,
			after:     `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":"*"}]}`,
			wantEqual: true,
		},
		{
			name:      "action list reordered and case-folded",
			strategy:  "aws_policy_json",
			before:    `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:PutObject","s3:getobject"],"Resource":"*"}]}`,
			after:     `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:PutObject"],"Resource":"*"}]}`,
			wantEqual: true,
		},
		{
			name:      "single statement object vs array of one",
			strategy:  "aws_policy_json",
			before:    `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"sts:AssumeRole","Principal":{"Service":"ec2.amazonaws.com"}}}`,
			after:     `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Principal":{"Service":"ec2.amazonaws.com"}}]}`,
			wantEqual: true,
		},
		{
			name:      "principal star vs AWS star",
			strategy:  "aws_policy_json",
			before:    `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Principal":"*"}]}`,
			after:     `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Principal":{"AWS":"*"}}]}`,
			wantEqual: true,
		},
		{
			name:      "condition bool coerced to string",
			strategy:  "aws_policy_json",
			before:    `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"Bool":{"aws:MultiFactorAuthPresent":false}}}]}`,
			after:     `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"false"}}}]}`,
			wantEqual: true,
		},
		{
			name:      "account id principal vs root ARN (KMS canonical form)",
			strategy:  "aws_policy_json",
			before:    `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"kms:*","Resource":"*","Principal":{"AWS":"111122223333"}}]}`,
			after:     `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"kms:*","Resource":"*","Principal":{"AWS":"arn:aws:iam::111122223333:root"}}]}`,
			wantEqual: true,
		},
		{
			name:      "REAL: different account id principal",
			strategy:  "aws_policy_json",
			before:    `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"kms:*","Resource":"*","Principal":{"AWS":"111122223333"}}]}`,
			after:     `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"kms:*","Resource":"*","Principal":{"AWS":"arn:aws:iam::999988887777:root"}}]}`,
			wantEqual: false,
		},
		{
			name:      "REAL: 12-char non-numeric principal untouched",
			strategy:  "aws_policy_json",
			before:    `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"kms:*","Resource":"*","Principal":{"AWS":"AROAEXAMPLE1"}}]}`,
			after:     `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"kms:*","Resource":"*","Principal":{"AWS":"arn:aws:iam::AROAEXAMPLE1:root"}}]}`,
			wantEqual: false,
		},
		{
			name:      "duplicate action collapses",
			strategy:  "aws_policy_json",
			before:    `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:GetObject"],"Resource":"*"}]}`,
			after:     `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":"*"}]}`,
			wantEqual: true,
		},

		// ---- MUST stay real (false-positive guards) ----
		{
			name:      "REAL: action added",
			strategy:  "aws_policy_json",
			before:    `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":"*"}]}`,
			after:     `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:PutObject"],"Resource":"*"}]}`,
			wantEqual: false,
		},
		{
			name:      "REAL: effect flipped",
			strategy:  "aws_policy_json",
			before:    `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`,
			after:     `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"s3:GetObject","Resource":"*"}]}`,
			wantEqual: false,
		},
		{
			name:      "REAL: resource ARN case differs (ARN paths are case-sensitive)",
			strategy:  "aws_policy_json",
			before:    `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::Bucket/*"}]}`,
			after:     `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::bucket/*"}]}`,
			wantEqual: false,
		},
		{
			name:      "REAL: statement removed",
			strategy:  "aws_policy_json",
			before:    `{"Version":"2012-10-17","Statement":[{"Sid":"A","Effect":"Allow","Action":"s3:GetObject","Resource":"*"},{"Sid":"B","Effect":"Deny","Action":"s3:DeleteObject","Resource":"*"}]}`,
			after:     `{"Version":"2012-10-17","Statement":[{"Sid":"A","Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`,
			wantEqual: false,
		},
		{
			name:      "REAL: condition value changed",
			strategy:  "aws_policy_json",
			before:    `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*","Condition":{"StringEquals":{"aws:SourceVpc":"vpc-111"}}}]}`,
			after:     `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*","Condition":{"StringEquals":{"aws:SourceVpc":"vpc-222"}}}]}`,
			wantEqual: false,
		},
		{
			name:      "REAL: principal account changed",
			strategy:  "aws_policy_json",
			before:    `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Principal":{"AWS":"arn:aws:iam::111111111111:root"}}]}`,
			after:     `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Principal":{"AWS":"arn:aws:iam::222222222222:root"}}]}`,
			wantEqual: false,
		},
		{
			name:      "REAL: principal star vs specific account",
			strategy:  "aws_policy_json",
			before:    `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Principal":{"AWS":"arn:aws:iam::111111111111:root"}}]}`,
			after:     `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Principal":"*"}]}`,
			wantEqual: false,
		},
		{
			name:      "REAL: version changed",
			strategy:  "aws_policy_json",
			before:    `{"Version":"2008-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`,
			after:     `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`,
			wantEqual: false,
		},
		{
			name:      "REAL: not valid JSON",
			strategy:  "aws_policy_json",
			before:    `{"Version":"2012-10-17",`,
			after:     `{"Version":"2012-10-17"}`,
			wantEqual: false,
		},
		{
			// "*" excludes everyone; {"AWS":"*"} excludes only AWS principals.
			// In NotPrincipal that difference changes what a Deny denies.
			name:      "REAL: NotPrincipal star vs AWS star is NOT collapsed",
			strategy:  "aws_policy_json",
			before:    `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"s3:*","Resource":"*","NotPrincipal":"*"}]}`,
			after:     `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"s3:*","Resource":"*","NotPrincipal":{"AWS":"*"}}]}`,
			wantEqual: false,
		},
		{
			// Same "*" ≡ {"AWS":"*"} asymmetry, this time on Principal under a
			// Deny: "*" denies everyone (incl. anonymous), {"AWS":"*"} denies only
			// AWS principals. Collapsing them would hide a real security change
			// (e.g. a DenyInsecureTransport that stops blocking anonymous HTTP).
			name:      "REAL: Deny Principal star vs AWS star is NOT collapsed",
			strategy:  "aws_policy_json",
			before:    `{"Version":"2012-10-17","Statement":[{"Sid":"DenyInsecure","Effect":"Deny","Action":"s3:*","Resource":"*","Principal":"*","Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}`,
			after:     `{"Version":"2012-10-17","Statement":[{"Sid":"DenyInsecure","Effect":"Deny","Action":"s3:*","Resource":"*","Principal":{"AWS":"*"},"Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}`,
			wantEqual: false,
		},
		{
			// The Allow counterpart MUST still collapse — this is the legitimate
			// public-bucket perma-diff S3 actually produces, and the fix's gate
			// must not regress it.
			name:      "Allow Principal star vs AWS star still collapses",
			strategy:  "aws_policy_json",
			before:    `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Principal":"*"}]}`,
			after:     `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Principal":{"AWS":"*"}}]}`,
			wantEqual: true,
		},
		{
			name:      "NotPrincipal scalar vs single-element list still equal",
			strategy:  "aws_policy_json",
			before:    `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"s3:*","Resource":"*","NotPrincipal":{"AWS":"arn:aws:iam::111122223333:root"}}]}`,
			after:     `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"s3:*","Resource":"*","NotPrincipal":{"AWS":["arn:aws:iam::111122223333:root"]}}]}`,
			wantEqual: true,
		},
		{
			// A decoder that stops at the first JSON value would treat the
			// appended public-access statement as noise.
			name:      "REAL: trailing JSON content is rejected",
			strategy:  "aws_policy_json",
			before:    `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`,
			after:     `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:*","Resource":"*"}]}`,
			wantEqual: false,
		},
		{
			name:      "REAL: non-string input",
			strategy:  "aws_policy_json",
			before:    map[string]any{"Version": "2012-10-17"},
			after:     `{"Version":"2012-10-17"}`,
			wantEqual: false,
		},
	})
}

func TestGenericJSON(t *testing.T) {
	runCases(t, []canonCase{
		{
			name:      "whitespace and key order",
			strategy:  "generic_json",
			before:    `{"b":1,"a":{"y":true,"x":null}}`,
			after:     "{\n  \"a\": {\"x\": null, \"y\": true},\n  \"b\": 1\n}",
			wantEqual: true,
		},
		{
			name:      "REAL: array order differs (order significant for unknown arrays)",
			strategy:  "generic_json",
			before:    `{"steps":["a","b"]}`,
			after:     `{"steps":["b","a"]}`,
			wantEqual: false,
		},
		{
			name:      "REAL: value changed",
			strategy:  "generic_json",
			before:    `{"timeout":30}`,
			after:     `{"timeout":60}`,
			wantEqual: false,
		},
		{
			name:      "REAL: bare scalar strings are not JSON containers",
			strategy:  "generic_json",
			before:    `80`,
			after:     `80`,
			wantEqual: false,
		},
		{
			// Regression guard: with float64 decoding these two DIFFERENT
			// integers collapse to the same float and compare equal.
			name:      "REAL: large integers beyond float64 precision differ",
			strategy:  "generic_json",
			before:    `{"x":9007199254740993}`,
			after:     `{"x":9007199254740992}`,
			wantEqual: false,
		},
		{
			name:      "large integers exactly equal",
			strategy:  "generic_json",
			before:    `{"x":9007199254740993}`,
			after:     `{ "x": 9007199254740993 }`,
			wantEqual: true,
		},
	})
}

func TestSetList(t *testing.T) {
	runCases(t, []canonCase{
		{
			name:      "subnet ids reordered",
			strategy:  "set_list",
			before:    []any{"subnet-a", "subnet-b", "subnet-c"},
			after:     []any{"subnet-c", "subnet-a", "subnet-b"},
			wantEqual: true,
		},
		{
			name:      "REAL: element replaced",
			strategy:  "set_list",
			before:    []any{"subnet-a", "subnet-b"},
			after:     []any{"subnet-a", "subnet-z"},
			wantEqual: false,
		},
		{
			name:      "REAL: element added",
			strategy:  "set_list",
			before:    []any{"sg-1"},
			after:     []any{"sg-1", "sg-2"},
			wantEqual: false,
		},
		{
			name:      "REAL: duplicate vs single is not collapsed",
			strategy:  "set_list",
			before:    []any{"a", "a"},
			after:     []any{"a"},
			wantEqual: false,
		},
	})
}

func TestScalarCoercion(t *testing.T) {
	runCases(t, []canonCase{
		{name: "string vs number", strategy: "scalar_coercion", before: "80", after: float64(80), wantEqual: true},
		{name: "number vs string", strategy: "scalar_coercion", before: float64(443), after: "443", wantEqual: true},
		{name: "string vs bool", strategy: "scalar_coercion", before: "true", after: true, wantEqual: true},
		{name: "REAL: different numbers", strategy: "scalar_coercion", before: "80", after: float64(8080), wantEqual: false},
		{name: "REAL: 1 is not true", strategy: "scalar_coercion", before: "1", after: true, wantEqual: false},
		{name: "REAL: TRUE is not coerced (case unknown to API)", strategy: "scalar_coercion", before: "TRUE", after: true, wantEqual: false},
		{name: "REAL: padded number string", strategy: "scalar_coercion", before: " 80", after: float64(80), wantEqual: false},
		{name: "REAL: two plain strings", strategy: "scalar_coercion", before: "80", after: "080", wantEqual: false},
		{name: "json.Number vs string", strategy: "scalar_coercion", before: json.Number("443"), after: "443", wantEqual: true},
		{name: "REAL: large int string vs near-miss json.Number", strategy: "scalar_coercion", before: "9007199254740993", after: json.Number("9007199254740992"), wantEqual: false},
		{name: "scientific notation equals plain (numerically identical)", strategy: "scalar_coercion", before: "100", after: json.Number("1e2"), wantEqual: true},
	})
}

func TestDNSName(t *testing.T) {
	runCases(t, []canonCase{
		{name: "trailing dot", strategy: "dns_name", before: "www.example.com.", after: "www.example.com", wantEqual: true},
		{name: "case", strategy: "dns_name", before: "WWW.Example.COM", after: "www.example.com", wantEqual: true},
		{name: "wildcard escape", strategy: "dns_name", before: `\052.example.com`, after: "*.example.com", wantEqual: true},
		{name: "REAL: different host", strategy: "dns_name", before: "www.example.com", after: "api.example.com", wantEqual: false},
		{name: "REAL: subdomain added", strategy: "dns_name", before: "example.com", after: "www.example.com", wantEqual: false},
	})
}

func TestEmptyCollection(t *testing.T) {
	runCases(t, []canonCase{
		{name: "null vs empty map", strategy: "empty_collection", before: nil, after: map[string]any{}, wantEqual: true},
		{name: "empty map vs null", strategy: "empty_collection", before: map[string]any{}, after: nil, wantEqual: true},
		{name: "null vs empty list", strategy: "empty_collection", before: nil, after: []any{}, wantEqual: true},
		{name: "REAL: map gained a key", strategy: "empty_collection", before: nil, after: map[string]any{"Team": "core"}, wantEqual: false},
		{name: "REAL: map lost its keys", strategy: "empty_collection", before: map[string]any{"Team": "core"}, after: map[string]any{}, wantEqual: false},
		{name: "REAL: empty string not empty by default", strategy: "empty_collection", before: nil, after: "", wantEqual: false},
		{name: "empty string allowed via opts", strategy: "empty_collection", before: nil, after: "", opts: map[string]any{"empty_string": true}, wantEqual: true},
	})
}

func TestSGRules(t *testing.T) {
	rule := func(port float64, cidrs []any, desc any) map[string]any {
		return map[string]any{
			"from_port":   port,
			"to_port":     port,
			"protocol":    "tcp",
			"cidr_blocks": cidrs,
			"description": desc,
			"self":        false,
		}
	}
	runCases(t, []canonCase{
		{
			name:      "rule order and cidr order shuffled",
			strategy:  "sg_rules",
			before:    []any{rule(443, []any{"10.0.0.0/8", "172.16.0.0/12"}, "https"), rule(80, []any{"0.0.0.0/0"}, "http")},
			after:     []any{rule(80, []any{"0.0.0.0/0"}, "http"), rule(443, []any{"172.16.0.0/12", "10.0.0.0/8"}, "https")},
			wantEqual: true,
		},
		{
			name:      "null vs empty description",
			strategy:  "sg_rules",
			before:    []any{rule(80, []any{"0.0.0.0/0"}, nil)},
			after:     []any{rule(80, []any{"0.0.0.0/0"}, "")},
			wantEqual: true,
		},
		{
			name:      "REAL: port changed",
			strategy:  "sg_rules",
			before:    []any{rule(80, []any{"0.0.0.0/0"}, "web")},
			after:     []any{rule(8080, []any{"0.0.0.0/0"}, "web")},
			wantEqual: false,
		},
		{
			name:      "REAL: cidr widened",
			strategy:  "sg_rules",
			before:    []any{rule(443, []any{"10.0.0.0/8"}, "internal")},
			after:     []any{rule(443, []any{"0.0.0.0/0"}, "internal")},
			wantEqual: false,
		},
		{
			name:      "REAL: rule added",
			strategy:  "sg_rules",
			before:    []any{rule(443, []any{"10.0.0.0/8"}, "x")},
			after:     []any{rule(443, []any{"10.0.0.0/8"}, "x"), rule(22, []any{"0.0.0.0/0"}, "ssh")},
			wantEqual: false,
		},
		{
			name:      "REAL but noted: description-only edit carries ForceNew advisory",
			strategy:  "sg_rules",
			before:    []any{rule(443, []any{"10.0.0.0/8"}, "old text")},
			after:     []any{rule(443, []any{"10.0.0.0/8"}, "new text")},
			wantEqual: false,
			wantNote:  true,
		},
	})
}

func TestECSContainerDefinitions(t *testing.T) {
	runCases(t, []canonCase{
		{
			name:      "env order, key order, numeric env value, API defaults injected",
			strategy:  "ecs_container_definitions",
			before:    `[{"name":"app","image":"repo/app:1.2.3","essential":true,"environment":[{"name":"PORT","value":8080},{"name":"ENV","value":"prod"}],"portMappings":[{"containerPort":8080,"protocol":"tcp"}]}]`,
			after:     `[{"cpu":0,"environment":[{"name":"ENV","value":"prod"},{"name":"PORT","value":"8080"}],"image":"repo/app:1.2.3","mountPoints":[],"name":"app","portMappings":[{"containerPort":8080}],"systemControls":[],"volumesFrom":[]}]`,
			wantEqual: true,
		},
		{
			name:      "container order swapped",
			strategy:  "ecs_container_definitions",
			before:    `[{"name":"app","image":"a:1"},{"name":"sidecar","image":"s:1"}]`,
			after:     `[{"name":"sidecar","image":"s:1"},{"name":"app","image":"a:1"}]`,
			wantEqual: true,
		},
		{
			name:      "REAL: image tag bumped",
			strategy:  "ecs_container_definitions",
			before:    `[{"name":"app","image":"repo/app:1.2.3"}]`,
			after:     `[{"name":"app","image":"repo/app:1.2.4"}]`,
			wantEqual: false,
		},
		{
			name:      "REAL: env var value changed",
			strategy:  "ecs_container_definitions",
			before:    `[{"name":"app","image":"a:1","environment":[{"name":"LOG_LEVEL","value":"info"}]}]`,
			after:     `[{"name":"app","image":"a:1","environment":[{"name":"LOG_LEVEL","value":"debug"}]}]`,
			wantEqual: false,
		},
		{
			name:      "REAL: env var removed",
			strategy:  "ecs_container_definitions",
			before:    `[{"name":"app","image":"a:1","environment":[{"name":"A","value":"1"},{"name":"B","value":"2"}]}]`,
			after:     `[{"name":"app","image":"a:1","environment":[{"name":"A","value":"1"}]}]`,
			wantEqual: false,
		},
		{
			name:      "REAL: essential explicitly false is not a default",
			strategy:  "ecs_container_definitions",
			before:    `[{"name":"app","image":"a:1","essential":true}]`,
			after:     `[{"name":"app","image":"a:1","essential":false}]`,
			wantEqual: false,
		},
		{
			name:      "REAL: cpu 256 is not the 0 default",
			strategy:  "ecs_container_definitions",
			before:    `[{"name":"app","image":"a:1","cpu":256}]`,
			after:     `[{"name":"app","image":"a:1"}]`,
			wantEqual: false,
		},
		{
			name:      "REAL: container added",
			strategy:  "ecs_container_definitions",
			before:    `[{"name":"app","image":"a:1"}]`,
			after:     `[{"name":"app","image":"a:1"},{"name":"sidecar","image":"s:1"}]`,
			wantEqual: false,
		},
		{
			name:      "REAL: hostPort changed (not normalised away)",
			strategy:  "ecs_container_definitions",
			before:    `[{"name":"app","image":"a:1","portMappings":[{"containerPort":80,"hostPort":80}]}]`,
			after:     `[{"name":"app","image":"a:1","portMappings":[{"containerPort":80}]}]`,
			wantEqual: false,
		},
		{
			// ECS resolves duplicate env names positionally (last wins), so
			// reordering duplicates changes the effective value — sorting must
			// not equate these.
			name:      "REAL: duplicate env names reordered (last-wins)",
			strategy:  "ecs_container_definitions",
			before:    `[{"name":"app","image":"a:1","environment":[{"name":"MODE","value":"safe"},{"name":"MODE","value":"fast"}]}]`,
			after:     `[{"name":"app","image":"a:1","environment":[{"name":"MODE","value":"fast"},{"name":"MODE","value":"safe"}]}]`,
			wantEqual: false,
		},
		{
			name:      "duplicate env names in identical order still equal",
			strategy:  "ecs_container_definitions",
			before:    `[{"name":"app","image":"a:1","environment":[{"name":"MODE","value":"safe"},{"name":"MODE","value":"fast"}],"cpu":0}]`,
			after:     `[{"name":"app","image":"a:1","environment":[{"name":"MODE","value":"safe"},{"name":"MODE","value":"fast"}]}]`,
			wantEqual: true,
		},
		{
			name:      "REAL: duplicate systemControls namespaces reordered",
			strategy:  "ecs_container_definitions",
			before:    `[{"name":"app","image":"a:1","systemControls":[{"namespace":"net.core.somaxconn","value":"511"},{"namespace":"net.core.somaxconn","value":"1024"}]}]`,
			after:     `[{"name":"app","image":"a:1","systemControls":[{"namespace":"net.core.somaxconn","value":"1024"},{"namespace":"net.core.somaxconn","value":"511"}]}]`,
			wantEqual: false,
		},
		{
			// Docker/runc apply rlimits sequentially — last duplicate name
			// wins, so this reorder changes the effective nofile limit.
			name:      "REAL: duplicate ulimit names reordered (last-wins)",
			strategy:  "ecs_container_definitions",
			before:    `[{"name":"app","image":"a:1","ulimits":[{"name":"nofile","softLimit":1024,"hardLimit":2048},{"name":"nofile","softLimit":4096,"hardLimit":8192}]}]`,
			after:     `[{"name":"app","image":"a:1","ulimits":[{"name":"nofile","softLimit":4096,"hardLimit":8192},{"name":"nofile","softLimit":1024,"hardLimit":2048}]}]`,
			wantEqual: false,
		},
		{
			name:      "distinct ulimit names reordered still equal",
			strategy:  "ecs_container_definitions",
			before:    `[{"name":"app","image":"a:1","ulimits":[{"name":"nofile","softLimit":1024,"hardLimit":2048},{"name":"nproc","softLimit":512,"hardLimit":512}]}]`,
			after:     `[{"name":"app","image":"a:1","ulimits":[{"name":"nproc","softLimit":512,"hardLimit":512},{"name":"nofile","softLimit":1024,"hardLimit":2048}]}]`,
			wantEqual: true,
		},
	})
}
