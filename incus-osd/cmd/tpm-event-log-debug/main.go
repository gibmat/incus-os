package main

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/google/go-eventlog/tcg"

	"github.com/lxc/incus-os/incus-osd/internal/secureboot"
	"github.com/lxc/incus-os/incus-osd/internal/util"
)

var systemdStubGUID = [16]byte{0xf8, 0xd1, 0xc5, 0x55, 0xcd, 0x4, 0xb5, 0x46, 0x8a, 0x20, 0xe5, 0x6c, 0xbb, 0x30, 0x52, 0xd0}

func main() {
	err := compareTPMEventLogs(os.Args[1], os.Args[2])
	if err != nil {
		fmt.Printf("ERROR: "+ err.Error() + "\n")
	}
}

func compareTPMEventLogs(logfile string, newUKIFile string) error {
	tpmEventLog, err := secureboot.GetValidatedTPMEventLog()
	if err != nil {
		return err
	}

	type retStruct struct {
		EventLog []tcg.Event `json:"event_log"`
		PCR4     string      `json:"pcr4"`
		PCR7     string      `json:"pcr7"`
	}

	fd, err := os.Open(logfile)
	if err != nil {
		return err
	}
	defer fd.Close()

	retStructData := &retStruct{}

	err = json.NewDecoder(fd).Decode(retStructData)
	if err != nil {
		return err
	}

	fileEventLog := retStructData.EventLog

	///////////////////////////////

	fmt.Printf("Inspecting provided TPM event log:\n")

	expectPCR4EFIAction, pcr4File, pcr7File := processEventLog(fileEventLog, true)

	fmt.Printf("\nInspecting current TPM event log:\n")

	_, pcr4TPM, pcr7TPM := processEventLog(tpmEventLog, expectPCR4EFIAction)

	fmt.Printf("\nReported PCR4 from file: %s\n", retStructData.PCR4)
	fmt.Printf("Computed PCR4 from file: %s\n", hex.EncodeToString(pcr4File))
	fmt.Printf("Computed PCR4 from TPM:  %s\n", hex.EncodeToString(pcr4TPM))

	fmt.Printf("\nReported PCR7 from file: %s\n", retStructData.PCR7)
	fmt.Printf("Computed PCR7 from file: %s\n", hex.EncodeToString(pcr7File))
	fmt.Printf("Computed PCR7 from TPM:  %s\n", hex.EncodeToString(pcr7TPM))

	///////////////////////////////

	futurePCR4, _ := secureboot.ComputeNewPCR4Value(fileEventLog, newUKIFile)
	fmt.Printf("\nPredicted PCR4 for new UKI:  %s\n", hex.EncodeToString(futurePCR4))

	return nil
}

func processEventLog(eventLog []tcg.Event, expectPCR4EFIAction bool) (bool, []byte, []byte) {
	hasPCR4EFIAction := false
	computedPCR4 := make([]byte, 32)
	computedPCR7 := make([]byte, 32)

	for _, e := range eventLog {
		if e.Index == 4 {
			if e.Type == tcg.EFIAction {
				hasPCR4EFIAction = true

				if !expectPCR4EFIAction {
					fmt.Printf("  PCR4: Skipping EFIAction event, since it wasn't present in provided TPM event log.\n")

					continue
				}
			}

			hash := crypto.SHA256.New()
			_, _ = hash.Write(computedPCR4)
			_, _ = hash.Write(e.ReplayedDigest())
			computedPCR4 = hash.Sum(nil)

			fmt.Printf("  PCR4: %s\n", e.Type.String())
			fmt.Printf("    SHA256: %s\n", hex.EncodeToString(e.ReplayedDigest()))

			switch e.Type {
			case tcg.EFIAction:
				s := sha256.Sum256([]byte(tcg.CallingEFIApplication))

				if bytes.Equal(e.ReplayedDigest(), s[:]) {
					fmt.Printf("    Decoded: %s\n", tcg.CallingEFIApplication)
				}
			case tcg.EFIBootServicesApplication:
				r := bytes.NewReader(e.Data)
				efiImageLoad, _ := tcg.ParseEFIImageLoad(r)
				devPaths, _ := efiImageLoad.DevicePath()

				for _, dev := range devPaths {
					if dev.Type == tcg.MediaDevice && dev.Subtype == 3 {
						if bytes.Equal(systemdStubGUID[:], dev.Data) {
							fmt.Printf("    Decoded: authenticode of UKI's .linux section\n")
						}
					}

					if dev.Type == tcg.MediaDevice && dev.Subtype == 4 {
						peName, _ := util.UTF16ToString(dev.Data)

						fmt.Printf("    Decoded: PE binary %s\n", peName)
					}
				}
			}
		}

		if e.Index == 7 {
			hash := crypto.SHA256.New()
			_, _ = hash.Write(computedPCR7)
			_, _ = hash.Write(e.ReplayedDigest())
			computedPCR7 = hash.Sum(nil)

			fmt.Printf("  PCR7: %s\n", e.Type.String())
			fmt.Printf("    SHA256: %s\n", hex.EncodeToString(e.ReplayedDigest()))

			switch e.Type {
			case tcg.EFIVariableDriverConfig:
				v, _ := tcg.ParseUEFIVariableData(bytes.NewReader(e.Data))
				certs, _, _ := v.SignatureData()

				fmt.Printf("    Decoded: EFI variable %s\n", v.VarName())

				for _, c := range certs {
					fmt.Printf("      %s\n", c.Subject.String())
				}
			case tcg.EFIVariableAuthority:
				v, _ := tcg.ParseUEFIVariableData(bytes.NewReader(e.Data))
				va, _ := tcg.ParseUEFIVariableAuthority(v)

				fmt.Printf("    Decoded: %s\n", va.Certs[0].Subject.String())
			}
		}
	}

	return hasPCR4EFIAction, computedPCR4, computedPCR7
}
