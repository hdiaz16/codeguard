package attest

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// CommitFailure registra el error específico de un commit dentro del rango inspeccionado.
type CommitFailure struct {
	CommitSHA string `json:"commit_sha"`
	ShortMsg  string `json:"short_msg"`
	Err       string `json:"error"`
}

// RangeReport reporta el resultado de auditar un rango de commits en un PR o push.
type RangeReport struct {
	Range    string          `json:"range"`
	Total    int             `json:"total"`
	Valid    int             `json:"valid"`
	Failures []CommitFailure `json:"failures,omitempty"`
}

// VerifyRange audita exhaustivamente cada commit en el rango baseRef..headRef.
// No se detiene en el primer fallo (no fail-fast) para reportar todos los commits ilegítimos.
func VerifyRange(ctx context.Context, repoDir, baseRef, headRef string, verifier Verifier, opts VerifyOptions) (*RangeReport, error) {
	rangeSpec := fmt.Sprintf("%s..%s", baseRef, headRef)
	if baseRef == "" {
		rangeSpec = headRef
	}

	cmd := exec.CommandContext(ctx, "git", "log", "--format=%x1e%H%x1f%s%x1f%B%x1f%T%x1f%P%x1f%ae", rangeSpec)
	cmd.Dir = repoDir
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("attest: fallo al obtener historial de %s: %w", rangeSpec, err)
	}

	raw := string(out)
	if strings.TrimSpace(raw) == "" {
		return &RangeReport{Range: rangeSpec, Total: 0, Valid: 0}, nil
	}

	records := strings.Split(raw, "\x1e")
	report := &RangeReport{
		Range: rangeSpec,
	}

	for _, rec := range records {
		rec = strings.TrimSpace(rec)
		if rec == "" {
			continue
		}
		parts := strings.Split(rec, "\x1f")
		if len(parts) < 4 {
			continue
		}

		report.Total++
		commitSHA := strings.TrimSpace(parts[0])
		shortMsg := strings.TrimSpace(parts[1])
		fullMsg := parts[2]
		treeSHA := strings.TrimSpace(parts[3])

		var parentSHAs []string
		if len(parts) >= 5 && strings.TrimSpace(parts[4]) != "" {
			parentSHAs = strings.Fields(strings.TrimSpace(parts[4]))
		} else {
			parentSHAs = []string{}
		}

		var authorEmail string
		if len(parts) >= 6 {
			authorEmail = strings.TrimSpace(parts[5])
		}

		trailerVal, err := ExtractTrailer(fullMsg)
		if err != nil {
			report.Failures = append(report.Failures, CommitFailure{
				CommitSHA: commitSHA,
				ShortMsg:  shortMsg,
				Err:       err.Error(),
			})
			continue
		}

		att, err := Decode(trailerVal)
		if err != nil {
			report.Failures = append(report.Failures, CommitFailure{
				CommitSHA: commitSHA,
				ShortMsg:  shortMsg,
				Err:       fmt.Sprintf("decodificación falló: %v", err),
			})
			continue
		}

		commitOpts := opts
		commitOpts.ExpectedTreeSHA = treeSHA
		if len(att.Claims.ParentSHAs) > 0 {
			commitOpts.ExpectedParentSHAs = parentSHAs
		}
		if att.Claims.AuthorEmail != "" {
			commitOpts.ExpectedAuthor = authorEmail
		}

		if err := verifier.Verify(att, commitOpts); err != nil {
			report.Failures = append(report.Failures, CommitFailure{
				CommitSHA: commitSHA,
				ShortMsg:  shortMsg,
				Err:       err.Error(),
			})
			continue
		}

		report.Valid++
	}

	if len(report.Failures) > 0 {
		return report, fmt.Errorf("attest: %d de %d commits fallaron la verificación de atestación en %s",
			len(report.Failures), report.Total, rangeSpec)
	}

	return report, nil
}
