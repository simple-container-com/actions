// Test fixtures for semgrep-scan/rules/pulumi-iac.yml.
//
// Lines marked `// ruleid: <id>` MUST match that rule.
// Lines marked `// ok: <id>` MUST NOT match that rule.
//
// This file is never compiled; only Semgrep parses it. Qualified package
// identifiers (`corev1`, `storage`, `compute`, `ec2`, `pulumi`) need not be
// importable — go/parser accepts unresolved selectors at the AST level.
// The `//go:build ignore` tag silences IDE / `go build` complaints; the
// fixture is reached only via direct Semgrep targeting in run-tests.sh.

//go:build ignore

package pulumifixtures

// --------------------------------------------------------------------
// go-pulumi-k8s-privileged-workload
// --------------------------------------------------------------------

func k8sPrivileged() {
	// ruleid: go-pulumi-k8s-privileged-workload
	_ = corev1.SecurityContextArgs{Privileged: pulumi.Bool(true)}
}

func k8sHostNetwork() {
	// ruleid: go-pulumi-k8s-privileged-workload
	_ = corev1.PodSpecArgs{HostNetwork: pulumi.Bool(true)}
}

func k8sHostPID() {
	// ruleid: go-pulumi-k8s-privileged-workload
	_ = corev1.PodSpecArgs{HostPID: pulumi.Bool(true)}
}

func k8sHostPathVolume() {
	// HostPath volume → fire (4th alternative of the rule).
	// ruleid: go-pulumi-k8s-privileged-workload
	_ = corev1.VolumeArgs{HostPath: hostPathArgs("/")}
}

func k8sSecure() {
	// SecurityContextArgs without Privileged → must NOT fire.
	// ok: go-pulumi-k8s-privileged-workload
	_ = corev1.SecurityContextArgs{RunAsNonRoot: pulumi.Bool(true)}
}

func k8sPodSpecNoHostFlags() {
	// PodSpecArgs without HostNetwork/HostPID → must NOT fire.
	// ok: go-pulumi-k8s-privileged-workload
	_ = corev1.PodSpecArgs{Containers: nil}
}

// --------------------------------------------------------------------
// go-pulumi-gcp-storage-public-access
// --------------------------------------------------------------------

func gcpStorageAllUsers() {
	// ruleid: go-pulumi-gcp-storage-public-access
	_ = storage.BucketIAMMemberArgs{Member: pulumi.String("allUsers"), Role: pulumi.String("roles/storage.objectViewer")}
}

func gcpStorageAllAuth() {
	// ruleid: go-pulumi-gcp-storage-public-access
	_ = storage.BucketIAMMemberArgs{Member: pulumi.String("allAuthenticatedUsers"), Role: pulumi.String("roles/storage.objectViewer")}
}

func gcpStorageUBLAOff() {
	// ruleid: go-pulumi-gcp-storage-public-access
	_ = storage.BucketArgs{UniformBucketLevelAccess: pulumi.Bool(false), Location: pulumi.String("us")}
}

func gcpStorageScopedGroup() {
	// Specific group principal → must NOT fire.
	// ok: go-pulumi-gcp-storage-public-access
	_ = storage.BucketIAMMemberArgs{Member: pulumi.String("group:admins@example.com"), Role: pulumi.String("roles/storage.admin")}
}

func gcpStorageUBLAOn() {
	// ok: go-pulumi-gcp-storage-public-access
	_ = storage.BucketArgs{UniformBucketLevelAccess: pulumi.Bool(true), Location: pulumi.String("us")}
}

// --------------------------------------------------------------------
// go-pulumi-gcp-compute-default-sa-cloud-platform
// --------------------------------------------------------------------
// Two-pattern AND: AST `compute.InstanceArgs{...ServiceAccount:...}` +
// regex anchored on `cloud-platform` within ~600 chars of `compute.InstanceArgs{`.

func gcpComputeDefaultSACloudPlatform() {
	// Inline ServiceAccount + Scopes (no helper indirection) so the
	// regex anchor `Scopes:[\s\S]{0,200}cloud-platform` lands inside the
	// `compute.InstanceArgs{...}` body.
	// ruleid: go-pulumi-gcp-compute-default-sa-cloud-platform
	_ = compute.InstanceArgs{
		ServiceAccount: &compute.InstanceServiceAccountArgs{
			Email:  pulumi.String("default"),
			Scopes: pulumi.StringArray{pulumi.String("https://www.googleapis.com/auth/cloud-platform")},
		},
	}
}

func gcpComputeNarrowScope() {
	// Custom SA + narrow read-only scope (no `cloud-platform`) → must NOT fire.
	// ok: go-pulumi-gcp-compute-default-sa-cloud-platform
	_ = compute.InstanceArgs{
		ServiceAccount: &compute.InstanceServiceAccountArgs{
			Email:  pulumi.String("custom-sa@project.iam.gserviceaccount.com"),
			Scopes: pulumi.StringArray{pulumi.String("https://www.googleapis.com/auth/devstorage.read_only")},
		},
	}
}

// --------------------------------------------------------------------
// go-pulumi-aws-sg-open-ingress
// --------------------------------------------------------------------

func awsSGOpenIngress() {
	// Inline CidrBlocks so the rule's `CidrBlocks: pulumi.StringArray{...
	// "0.0.0.0/0"` regex anchor lands here.
	// ruleid: go-pulumi-aws-sg-open-ingress
	_ = ec2.SecurityGroupArgs{
		Ingress: ec2.SecurityGroupIngressArray{
			ec2.SecurityGroupIngressArgs{
				CidrBlocks: pulumi.StringArray{pulumi.String("0.0.0.0/0")},
				Protocol:   pulumi.String("tcp"),
				FromPort:   pulumi.Int(22),
				ToPort:     pulumi.Int(22),
			},
		},
	}
}

func awsSGScoped() {
	// Restricted ingress → must NOT fire (CIDR isn't 0.0.0.0/0).
	// ok: go-pulumi-aws-sg-open-ingress
	_ = ec2.SecurityGroupArgs{
		Ingress: ec2.SecurityGroupIngressArray{
			ec2.SecurityGroupIngressArgs{
				CidrBlocks: pulumi.StringArray{pulumi.String("10.0.0.0/8")},
				Protocol:   pulumi.String("tcp"),
				FromPort:   pulumi.Int(443),
				ToPort:     pulumi.Int(443),
			},
		},
	}
}

// --------------------------------------------------------------------
// go-pulumi-iam-wildcard-policy
// --------------------------------------------------------------------
// Rule is two `pattern-regex` variants over raw file text — markers
// preceed a single-line const containing the policy JSON so the
// validator can resolve `target = const line` cleanly.

// ruleid: go-pulumi-iam-wildcard-policy
const iamPolicyBadAction = `{"Action": "*", "Resource": "arn:aws:s3:::specific-bucket/*", "Effect": "Allow"}`

// ruleid: go-pulumi-iam-wildcard-policy
const iamPolicyBadResource = `{"Action": "s3:GetObject", "Resource": "*", "Effect": "Allow"}`

// ok: go-pulumi-iam-wildcard-policy
const iamPolicyOk = `{"Action": "s3:GetObject", "Resource": "arn:aws:s3:::specific-bucket/*", "Effect": "Allow"}`

// --------------------------------------------------------------------
// Stubs — Semgrep doesn't compile this, but `go/parser` is happier when
// the call sites resolve to declared identifiers in the same file.
// --------------------------------------------------------------------

func hostPathArgs(_ string) interface{}                    { return nil }
func serviceAccountArgs(_ string, _ []string) interface{}  { return nil }
func securityGroupIngress(_ string, _ int) interface{}     { return nil }
