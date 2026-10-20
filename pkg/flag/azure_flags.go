package flag

import (
	"time"

	"golang.org/x/xerrors"
)

// maxAzureSASDuration is the longest SAS Azure grants for a snapshot.
const maxAzureSASDuration = 60 * 24 * time.Hour

var azureSASDurationFlag = Flag[time.Duration]{
	Name:       "azure-sas-duration",
	ConfigName: "azure.sas-duration",
	// Short, because a SAS that a crashed scan leaves unrevoked stays valid
	// this long.
	Default:       time.Hour,
	Usage:         "lifetime of the read SAS granted for an Azure snapshot, which must outlast the scan",
	TelemetrySafe: true,
}

type AzureFlagGroup struct {
	SASDuration *Flag[time.Duration]
}

type AzureOptions struct {
	SASDuration time.Duration
}

func NewAzureFlagGroup() *AzureFlagGroup {
	return &AzureFlagGroup{
		SASDuration: azureSASDurationFlag.Clone(),
	}
}

func (f *AzureFlagGroup) Name() string {
	return "Azure"
}

func (f *AzureFlagGroup) Flags() []Flagger {
	return []Flagger{
		f.SASDuration,
	}
}

func (f *AzureFlagGroup) ToOptions(opts *Options) error {
	sasDuration := f.SASDuration.Value()
	if sasDuration < time.Second || sasDuration > maxAzureSASDuration {
		return xerrors.Errorf("--%s must be between 1s and %s: %s", f.SASDuration.Name, maxAzureSASDuration, sasDuration)
	}
	opts.AzureOptions = AzureOptions{
		SASDuration: sasDuration,
	}
	return nil
}
