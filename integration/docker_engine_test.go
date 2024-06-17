//go:build integration
// +build integration

package integration

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/aquasecurity/trivy/pkg/types"

	api "github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/stretchr/testify/require"
)

func TestDockerEngine(t *testing.T) {
	if *update {
		t.Skipf("This test doesn't update golden files")
	}
	tests := []struct {
		name          string
		imageTag      string
		invalidImage  bool
		ignoreUnfixed bool
		ignoreStatus  []string
		severity      []string
		ignoreIDs     []string
		input         string
		golden        string
		wantErr       string
	}{
		{
			name:     "alpine:3.9",
			imageTag: "ghcr.io/aquasecurity/trivy-test-images:alpine-39",
			input:    "testdata/fixtures/images/alpine-39.tar.gz",
			golden:   "testdata/alpine-39.json.golden",
		},
		{
			name: "alpine:3.9, with high and critical severity",
			severity: []string{
				"HIGH",
				"CRITICAL",
			},
			imageTag: "ghcr.io/aquasecurity/trivy-test-images:alpine-39",
			input:    "testdata/fixtures/images/alpine-39.tar.gz",
			golden:   "testdata/alpine-39-high-critical.json.golden",
		},
		{
			name:     "alpine:3.9, with .trivyignore",
			imageTag: "ghcr.io/aquasecurity/trivy-test-images:alpine-39",
			ignoreIDs: []string{
				"CVE-2019-1549",
				"CVE-2019-14697",
			},
			input:  "testdata/fixtures/images/alpine-39.tar.gz",
			golden: "testdata/alpine-39-ignore-cveids.json.golden",
		},
		{
			name:     "alpine:3.10",
			imageTag: "ghcr.io/aquasecurity/trivy-test-images:alpine-310",
			input:    "testdata/fixtures/images/alpine-310.tar.gz",
			golden:   "testdata/alpine-310.json.golden",
		},
		{
			name:     "amazonlinux:1",
			imageTag: "ghcr.io/aquasecurity/trivy-test-images:amazon-1",
			input:    "testdata/fixtures/images/amazon-1.tar.gz",
			golden:   "testdata/amazon-1.json.golden",
		},
		{
			name:     "amazonlinux:2",
			imageTag: "ghcr.io/aquasecurity/trivy-test-images:amazon-2",
			input:    "testdata/fixtures/images/amazon-2.tar.gz",
			golden:   "testdata/amazon-2.json.golden",
		},
		{
			name:     "almalinux 8",
			imageTag: "ghcr.io/aquasecurity/trivy-test-images:almalinux-8",
			input:    "testdata/fixtures/images/almalinux-8.tar.gz",
			golden:   "testdata/almalinux-8.json.golden",
		},
		{
			name:     "rocky linux 8",
			imageTag: "ghcr.io/aquasecurity/trivy-test-images:rockylinux-8",
			input:    "testdata/fixtures/images/rockylinux-8.tar.gz",
			golden:   "testdata/rockylinux-8.json.golden",
		},
		{
			name:     "centos 6",
			imageTag: "ghcr.io/aquasecurity/trivy-test-images:centos-6",
			input:    "testdata/fixtures/images/centos-6.tar.gz",
			golden:   "testdata/centos-6.json.golden",
		},
		{
			name:     "centos 7",
			imageTag: "ghcr.io/aquasecurity/trivy-test-images:centos-7",
			input:    "testdata/fixtures/images/centos-7.tar.gz",
			golden:   "testdata/centos-7.json.golden",
		},
		{
			name:          "centos 7, with --ignore-unfixed option",
			imageTag:      "ghcr.io/aquasecurity/trivy-test-images:centos-7",
			ignoreUnfixed: true,
			input:         "testdata/fixtures/images/centos-7.tar.gz",
			golden:        "testdata/centos-7-ignore-unfixed.json.golden",
		},
		{
			name:         "centos 7, with --ignore-status option",
			imageTag:     "ghcr.io/aquasecurity/trivy-test-images:centos-7",
			ignoreStatus: []string{"will_not_fix"},
			input:        "testdata/fixtures/images/centos-7.tar.gz",
			golden:       "testdata/centos-7-ignore-unfixed.json.golden",
		},
		{
			name:          "centos 7, with --ignore-unfixed option, with medium severity",
			imageTag:      "ghcr.io/aquasecurity/trivy-test-images:centos-7",
			ignoreUnfixed: true,
			severity:      []string{"MEDIUM"},
			input:         "testdata/fixtures/images/centos-7.tar.gz",
			golden:        "testdata/centos-7-medium.json.golden",
		},
		{
			name:     "registry.redhat.io/ubi7",
			imageTag: "ghcr.io/aquasecurity/trivy-test-images:ubi-7",
			input:    "testdata/fixtures/images/ubi-7.tar.gz",
			golden:   "testdata/ubi-7.json.golden",
		},
		{
			name:     "debian buster/10",
			imageTag: "ghcr.io/aquasecurity/trivy-test-images:debian-buster",
			input:    "testdata/fixtures/images/debian-buster.tar.gz",
			golden:   "testdata/debian-buster.json.golden",
		},
		{
			name:          "debian buster/10, with --ignore-unfixed option",
			ignoreUnfixed: true,
			imageTag:      "ghcr.io/aquasecurity/trivy-test-images:debian-buster",
			input:         "testdata/fixtures/images/debian-buster.tar.gz",
			golden:        "testdata/debian-buster-ignore-unfixed.json.golden",
		},
		{
			name:         "debian buster/10, with --ignore-status option",
			ignoreStatus: []string{"affected"},
			imageTag:     "ghcr.io/aquasecurity/trivy-test-images:debian-buster",
			input:        "testdata/fixtures/images/debian-buster.tar.gz",
			golden:       "testdata/debian-buster-ignore-unfixed.json.golden",
		},
		{
			name:     "debian stretch/9",
			imageTag: "ghcr.io/aquasecurity/trivy-test-images:debian-stretch",
			input:    "testdata/fixtures/images/debian-stretch.tar.gz",
			golden:   "testdata/debian-stretch.json.golden",
		},
		{
			name:     "distroless base",
			imageTag: "ghcr.io/aquasecurity/trivy-test-images:distroless-base",
			input:    "testdata/fixtures/images/distroless-base.tar.gz",
			golden:   "testdata/distroless-base.json.golden",
		},
		{
			name:     "distroless python2.7",
			imageTag: "ghcr.io/aquasecurity/trivy-test-images:distroless-python27",
			input:    "testdata/fixtures/images/distroless-python27.tar.gz",
			golden:   "testdata/distroless-python27.json.golden",
		},
		{
			name:     "oracle linux 8",
			imageTag: "ghcr.io/aquasecurity/trivy-test-images:oraclelinux-8",
			input:    "testdata/fixtures/images/oraclelinux-8.tar.gz",
			golden:   "testdata/oraclelinux-8.json.golden",
		},
		{
			name:     "ubuntu 18.04",
			imageTag: "ghcr.io/aquasecurity/trivy-test-images:ubuntu-1804",
			input:    "testdata/fixtures/images/ubuntu-1804.tar.gz",
			golden:   "testdata/ubuntu-1804.json.golden",
		},
		{
			name:          "ubuntu 18.04, with --ignore-unfixed option",
			imageTag:      "ghcr.io/aquasecurity/trivy-test-images:ubuntu-1804",
			ignoreUnfixed: true,
			input:         "testdata/fixtures/images/ubuntu-1804.tar.gz",
			golden:        "testdata/ubuntu-1804-ignore-unfixed.json.golden",
		},
		{
			name:     "opensuse leap 15.1",
			imageTag: "ghcr.io/aquasecurity/trivy-test-images:opensuse-leap-151",
			input:    "testdata/fixtures/images/opensuse-leap-151.tar.gz",
			golden:   "testdata/opensuse-leap-151.json.golden",
		},
		{
			name:     "photon 3.0",
			imageTag: "ghcr.io/aquasecurity/trivy-test-images:photon-30",
			input:    "testdata/fixtures/images/photon-30.tar.gz",
			golden:   "testdata/photon-30.json.golden",
		},
		{
			name:     "CBL-Mariner 1.0",
			imageTag: "ghcr.io/aquasecurity/trivy-test-images:mariner-1.0",
			input:    "testdata/fixtures/images/mariner-1.0.tar.gz",
			golden:   "testdata/mariner-1.0.json.golden",
		},
		{
			name:     "busybox with Cargo.lock",
			imageTag: "ghcr.io/aquasecurity/trivy-test-images:busybox-with-lockfile",
			input:    "testdata/fixtures/images/busybox-with-lockfile.tar.gz",
			golden:   "testdata/busybox-with-lockfile.json.golden",
		},
		{
			name:         "sad path, invalid image",
			invalidImage: true,
			input:        "badimage:latest",
			wantErr:      "unable to inspect the image (badimage:latest)",
		},
	}

	// Set up testing DB
	cacheDir := initDB(t)

	// Set a temp dir so that modules will not be loaded
	t.Setenv("XDG_DATA_HOME", cacheDir)

	ctx := context.Background()
	defer ctx.Done()

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	require.NoError(t, err)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !tt.invalidImage {
				testfile, err := os.Open(tt.input)
				require.NoError(t, err, tt.name)

				// ensure image doesnt already exists
				_, _ = cli.ImageRemove(ctx, tt.input, api.ImageRemoveOptions{
					Force:         true,
					PruneChildren: true,
				})

				// load image into docker engine
				res, err := cli.ImageLoad(ctx, testfile, true)
				require.NoError(t, err, tt.name)
				if _, err := io.Copy(io.Discard, res.Body); err != nil {
					require.NoError(t, err, tt.name)
				}
				defer res.Body.Close()

				// tag our image to something unique
				err = cli.ImageTag(ctx, tt.imageTag, tt.input)
				require.NoError(t, err, tt.name)

				// cleanup
				t.Cleanup(func() {
					_, _ = cli.ImageRemove(ctx, tt.input, api.ImageRemoveOptions{
						Force:         true,
						PruneChildren: true,
					})
					_, _ = cli.ImageRemove(ctx, tt.imageTag, api.ImageRemoveOptions{
						Force:         true,
						PruneChildren: true,
					})
				})
			}

			osArgs := []string{
				"--cache-dir",
				cacheDir,
				"image",
				"--skip-update",
				"--format=json",
			}

			if tt.ignoreUnfixed {
				osArgs = append(osArgs, "--ignore-unfixed")
			}

			if len(tt.ignoreStatus) != 0 {
				osArgs = append(osArgs,
					[]string{
						"--ignore-status",
						strings.Join(tt.ignoreStatus, ","),
					}...,
				)
			}
			if len(tt.severity) != 0 {
				osArgs = append(osArgs,
					[]string{
						"--severity",
						strings.Join(tt.severity, ","),
					}...,
				)
			}
			if len(tt.ignoreIDs) != 0 {
				trivyIgnore := ".trivyignore"
				err = os.WriteFile(trivyIgnore, []byte(strings.Join(tt.ignoreIDs, "\n")), 0444)
				require.NoError(t, err, "failed to write .trivyignore")
				defer os.Remove(trivyIgnore)
			}
			osArgs = append(osArgs, tt.input)

			// Run Trivy
			runTest(t, osArgs, tt.golden, "", types.FormatJSON, runOptions{
				wantErr: tt.wantErr,
				// Container field was removed in Docker Engine v26.0
				// cf. https://github.com/docker/cli/blob/v26.1.3/docs/deprecated.md#container-and-containerconfig-fields-in-image-inspect
				override: overrideFuncs(overrideUID, func(t *testing.T, want, _ *types.Report) {
					want.Metadata.ImageConfig.Container = ""
				}),
			})
		})
	}
}
