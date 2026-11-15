package syncstate

import (
	"compress/gzip"
	"io"
	"strings"

	"pluto/internal/syncproto"
)

func readMetadataResponse(body io.Reader, encoding string, limit int, negotiated bool) ([]byte, error) {
	compressed := &io.LimitedReader{R: body, N: int64(limit) + 1}
	var reader io.Reader = compressed
	if encoding != "" && encoding != "identity" {
		if !negotiated || !strings.EqualFold(encoding, "gzip") {
			return nil, syncproto.ErrContract
		}
		gzipReader, err := gzip.NewReader(compressed)
		if err != nil {
			return nil, err
		}
		defer gzipReader.Close()
		reader = gzipReader
	}
	raw, err := io.ReadAll(io.LimitReader(reader, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > limit || compressed.N <= 0 {
		return nil, syncproto.ErrLimit
	}
	return raw, nil
}
