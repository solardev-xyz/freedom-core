// Command bee-check is a one-off cross-check of dweb-verify.json's Swarm
// trees and manifests against Bee's own writers, at the commit design 0009
// pins (a93fb7a7). It isn't part of CI: run it by hand (see the README row in
// vectors/README.md), and it rewrites result.json, which the generator copies
// into the vectors' meta.
//
// For every file case it splits the same content with Bee's pipeline at the
// case's redundancy level; for the manifests Bee's upload handlers write
// (a single file, a directory, a feed) it repeats what those handlers do.
// Then it compares Bee's reference with the vector's.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/ethersphere/bee/v2/pkg/file/loadsave"
	"github.com/ethersphere/bee/v2/pkg/file/pipeline"
	"github.com/ethersphere/bee/v2/pkg/file/pipeline/builder"
	"github.com/ethersphere/bee/v2/pkg/file/redundancy"
	"github.com/ethersphere/bee/v2/pkg/manifest"
	"github.com/ethersphere/bee/v2/pkg/storage/inmemchunkstore"
	"github.com/ethersphere/bee/v2/pkg/swarm"
)

type file struct {
	ID         string `json:"id"`
	Seed       string `json:"seed"`
	Size       int    `json:"size"`
	Redundancy int    `json:"redundancy"`
	Root       string `json:"root"`
}

type entry struct {
	Path        string `json:"path"`
	DataRef     string `json:"data_ref"`
	ContentType string `json:"content_type"`
}

type mf struct {
	ID      string  `json:"id"`
	Root    string  `json:"root"`
	Entries []entry `json:"entries"`
}

type feed struct {
	ID       string `json:"id"`
	Owner    string `json:"owner"`
	Topic    string `json:"topic"`
	Manifest string `json:"manifest"`
}

type doc struct {
	Swarm struct {
		Files     []file `json:"files"`
		Manifests []mf   `json:"manifests"`
		Feeds     []feed `json:"feeds"`
	} `json:"swarm"`
}

type result struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	Vector string `json:"vector"`
	Bee    string `json:"bee"`
	Equal  bool   `json:"equal"`
}

// content is the generator's rule: SHA-256(seed ‖ u64_be(i)), concatenated.
func content(seed string, n int) []byte {
	out := make([]byte, 0, n+32)
	var i uint64
	for len(out) < n {
		h := sha256.New()
		h.Write([]byte(seed))
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], i)
		h.Write(b[:])
		out = h.Sum(out)
		i++
	}
	return out[:n]
}

func split(ctx context.Context, store *inmemchunkstore.ChunkStore, data []byte, level redundancy.Level) (swarm.Address, error) {
	p := builder.NewPipelineBuilder(ctx, store, false, level)
	return builder.FeedPipeline(ctx, p, bytes.NewReader(data))
}

func newManifest(ctx context.Context, store *inmemchunkstore.ChunkStore) (manifest.Interface, error) {
	factory := func() pipeline.Interface { return builder.NewPipelineBuilder(ctx, store, false, redundancy.NONE) }
	ls := loadsave.New(store, store, factory, redundancy.NONE)
	return manifest.NewDefaultManifest(ls, false)
}

func addr(s string) (swarm.Address, error) {
	b, err := hex.DecodeString(s)
	return swarm.NewAddress(b), err
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: bee-check <dweb-verify.json> <result.json>")
		os.Exit(2)
	}
	raw, err := os.ReadFile(os.Args[1])
	must(err)
	var d doc
	must(json.Unmarshal(raw, &d))
	ctx := context.Background()
	var out []result

	for _, f := range d.Swarm.Files {
		store := inmemchunkstore.New()
		ref, err := split(ctx, store, content(f.Seed, f.Size), redundancy.Level(f.Redundancy))
		must(err)
		out = append(out, result{f.ID, "file", f.Root, ref.String(), ref.String() == f.Root})
	}

	for _, m := range d.Swarm.Manifests {
		var kind string
		var root swarm.Address
		store := inmemchunkstore.New()
		mm, err := newManifest(ctx, store)
		must(err)
		switch {
		case strings.HasSuffix(m.ID, "-manifest"):
			// bzz.go fileUploadHandler.
			kind = "single-file manifest (bzz.go fileUploadHandler)"
			e := m.Entries[0]
			must(mm.Add(ctx, manifest.RootPath, manifest.NewEntry(swarm.ZeroAddress, map[string]string{
				manifest.WebsiteIndexDocumentSuffixKey: e.Path,
			})))
			ref, err := addr(e.DataRef)
			must(err)
			must(mm.Add(ctx, e.Path, manifest.NewEntry(ref, map[string]string{
				manifest.EntryMetadataContentTypeKey: e.ContentType,
				manifest.EntryMetadataFilenameKey:    e.Path,
			})))
		case m.ID == "site-a" || m.ID == "site-b" || m.ID == "site-c":
			// dirs.go storeDir.
			kind = "directory (dirs.go storeDir)"
			for _, e := range m.Entries {
				ref, err := addr(e.DataRef)
				must(err)
				name := e.Path[strings.LastIndex(e.Path, "/")+1:]
				must(mm.Add(ctx, e.Path, manifest.NewEntry(ref, map[string]string{
					manifest.EntryMetadataContentTypeKey: e.ContentType,
					manifest.EntryMetadataFilenameKey:    name,
				})))
			}
			md := map[string]string{}
			if m.ID != "site-c" {
				md[manifest.WebsiteIndexDocumentSuffixKey] = "index.html"
			}
			if m.ID == "site-b" {
				md[manifest.WebsiteErrorDocumentPathKey] = "error.html"
			}
			if len(md) > 0 {
				must(mm.Add(ctx, manifest.RootPath, manifest.NewEntry(swarm.ZeroAddress, md)))
			}
		default:
			continue
		}
		root, err = mm.Store(ctx)
		must(err)
		out = append(out, result{m.ID, kind, m.Root, root.String(), root.String() == m.Root})
	}

	for _, f := range d.Swarm.Feeds {
		store := inmemchunkstore.New()
		mm, err := newManifest(ctx, store)
		must(err)
		// feed.go feedPostHandler.
		must(mm.Add(ctx, "/", manifest.NewEntry(swarm.NewAddress(make([]byte, 32)), map[string]string{
			"swarm-feed-owner": f.Owner,
			"swarm-feed-topic": f.Topic,
			"swarm-feed-type":  "Sequence",
		})))
		root, err := mm.Store(ctx)
		must(err)
		out = append(out, result{f.ID, "feed manifest (feed.go feedPostHandler)", f.Manifest, root.String(), root.String() == f.Manifest})
	}

	text, err := json.MarshalIndent(map[string]any{
		"bee": map[string]string{
			"module": "github.com/ethersphere/bee/v2",
			"commit": "a93fb7a72c416a497193173e4c5739fd11cbb312",
		},
		"results": out,
	}, "", "  ")
	must(err)
	must(os.WriteFile(os.Args[2], append(text, '\n'), 0o644))
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
