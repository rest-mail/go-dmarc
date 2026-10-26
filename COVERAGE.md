# Coverage exceptions

CI fails when statement coverage of `./...` falls below 95%. The pinned RFC
proof uses `-coverpkg=./...`, so tests in `pkg/dmarc` also cover the internal
DNS, record grammar and report codec packages they exercise. These are the
statements left uncovered on purpose, each with the reason. Add an entry here
whenever you leave a statement uncovered.

| File | Function | Statements | Reason |
|------|----------|------------|--------|
| `pkg/dmarc/report.go` | `BuildReport` | `return nil, fmt.Errorf(...)` after `xml.MarshalIndent` | The report holds only strings and integers, which encoding/xml always marshals (invalid characters become U+FFFD); the error is still checked rather than ignored. |
| `pkg/dmarc/report.go` | `Gzip` | `return nil, err` after `zw.Write` | A gzip writer over a `bytes.Buffer` fails only if the buffer does, and a buffer's writes cannot fail (it panics when out of memory). |
| `pkg/dmarc/report.go` | `Gzip` | `return nil, err` after `zw.Close` | As above: closing flushes into the same buffer. |
| `internal/checklist/main.go` | `main` | `os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))` | Exiting the process cannot be tested in-process. All of the checker's logic is in `run`, which the tests cover; CI also runs the command itself. |
