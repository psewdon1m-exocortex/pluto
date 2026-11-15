package syncstate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"syscall"
)

// This process-local proof is not an upload artifact or remote authority. It
// permits a no-op only when the planner rechecks the exact source, L/B/R and
// owner/trust witnesses. A changed file must still create its own stream.
type streamSourceProof struct {
	source       SourceEntry
	sha256, link string
}

func streamSourceMatches(source SourceEntry, info os.FileInfo) bool {
	return info.Mode().IsRegular() && statIdentity(info) == source.FileIdentity && info.Size() == source.SizeBytes && info.ModTime().UnixNano() == source.MTimeNS && statCTime(info) == source.CTimeNS
}

func hashStableStreamSource(ctx context.Context, source SourceEntry, acquire func(context.Context) (func(), error)) (*streamSourceProof, error) {
	if acquire == nil || source.SizeBytes < 1 || source.SizeBytes > streamV2MaximumFileBytes || source.Kind != "file" || source.Presence != "PRESENT" || source.Ambiguous {
		return nil, ErrCaptureChanged
	}
	release, err := acquire(ctx)
	if err != nil {
		return nil, err
	}
	if release == nil {
		return nil, ErrIdentityConflict
	}
	defer release()
	incarnation, err := ObserveSourceIncarnation(source.SourceRootPath)
	if err != nil || incarnation.object != source.SourceObject {
		return nil, ErrCaptureChanged
	}
	link, err := linkGuard(source.PhysicalPath)
	if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(source.PhysicalPath, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !streamSourceMatches(source, before) {
		return nil, ErrCaptureChanged
	}
	whole := sha256.New()
	buffer := make([]byte, StreamChunkBytes)
	captureSourceReads.Add(1)
	for left := source.SizeBytes; left > 0; {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		n := int(min(left, int64(len(buffer))))
		read, e := io.ReadFull(file, buffer[:n])
		captureSourceBytes.Add(int64(read))
		if e != nil {
			return nil, e
		}
		whole.Write(buffer[:n])
		left -= int64(n)
	}
	after, err := file.Stat()
	if err != nil || !streamSourceMatches(source, after) {
		return nil, ErrCaptureChanged
	}
	current, err := os.Stat(source.PhysicalPath)
	if err != nil || !os.SameFile(before, current) || !streamSourceMatches(source, current) {
		return nil, ErrCaptureChanged
	}
	afterLink, err := linkGuard(source.PhysicalPath)
	if err != nil || link != afterLink {
		return nil, ErrCaptureChanged
	}
	incarnation, err = ObserveSourceIncarnation(source.SourceRootPath)
	if err != nil || incarnation.object != source.SourceObject {
		return nil, ErrCaptureChanged
	}
	return &streamSourceProof{source: source, sha256: hex.EncodeToString(whole.Sum(nil)), link: link}, nil
}

func (p *streamSourceProof) current(source SourceEntry) bool {
	if p == nil || p.source != source || !validHash(p.sha256) {
		return false
	}
	incarnation, err := ObserveSourceIncarnation(source.SourceRootPath)
	if err != nil || incarnation.object != source.SourceObject {
		return false
	}
	link, err := linkGuard(source.PhysicalPath)
	if err != nil || link != p.link {
		return false
	}
	info, err := os.Stat(source.PhysicalPath)
	return err == nil && streamSourceMatches(source, info)
}
