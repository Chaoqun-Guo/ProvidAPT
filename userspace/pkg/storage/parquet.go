package storage

// ParquetWriter provides columnar storage for large-scale provenance analysis.
// Implementation placeholder — will use github.com/xitongsys/parquet-go or arrow/parquet.
//
// Benefits over JSON:
//   - Compressed columnar format (5-10x space savings)
//   - Predicate pushdown for efficient querying
//   - Native integration with Spark, DuckDB, etc.
//
// Schema sketch (future):
//   event_type: int32
//   timestamp:  int64 (nanoseconds)
//   pid:        int32
//   ppid:       int32
//   uid:        int32
//   comm:       string (dictionary encoded)
//   filename:   string (dictionary encoded)
//   saddr:      bytes (optional, IPv4/IPv6)
//   daddr:      bytes (optional)
//   sport:      uint16 (optional)
//   dport:      uint16 (optional)
//   flags:      int32
