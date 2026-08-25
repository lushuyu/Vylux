package request

import (
	"strings"
	"testing"

	"Vylux/internal/queue"
)

func TestDecodeStructuredAudioProcess(t *testing.T) {
	body := `{
		"asset_type":"audio",
		"operation":"process",
		"source":{"hash":"hash123","key":"uploads/audio.flac"},
		"pipeline":{
			"package":{"hls":{"enabled":true,"profile":"stream_aac_standard"}},
			"downloads":[{"format":"mp3","bitrate":"192k"},{"format":"flac"}],
			"waveform":{"enabled":true,"profile":"waveform_standard","bins":1024}
		},
		"delivery":{"callback_url":"https://example.com/callback"}
	}`

	req, err := Decode(strings.NewReader(body))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if req.Type != queue.TypeAudioTranscode {
		t.Fatalf("type = %q, want %q", req.Type, queue.TypeAudioTranscode)
	}
	if req.Hash != "hash123" {
		t.Fatalf("hash = %q, want hash123", req.Hash)
	}
	if req.Source != "uploads/audio.flac" {
		t.Fatalf("source = %q, want uploads/audio.flac", req.Source)
	}
	if req.CallbackURL != "https://example.com/callback" {
		t.Fatalf("callback_url = %q", req.CallbackURL)
	}
	if req.Options["hls"] != true || req.Options["mp3"] != true || req.Options["flac"] != true {
		t.Fatalf("unexpected options: %#v", req.Options)
	}
	if req.Options["mp3_bitrate"] != "192k" {
		t.Fatalf("mp3_bitrate = %#v, want 192k", req.Options["mp3_bitrate"])
	}
	if req.Options["waveform"] != true || req.Options["waveform_bins"] != 1024 {
		t.Fatalf("unexpected waveform options: %#v", req.Options)
	}
}

func TestDecodeAudioCreate(t *testing.T) {
	body := `{
		"source":{"hash":"hash123","key":"uploads/audio.flac"},
		"pipeline":{
			"package":{"hls":{"enabled":true,"profile":"stream_aac_standard"}},
			"downloads":[{"profile":"download_mp3_high"}],
			"waveform":{"enabled":true,"profile":"waveform_standard","bins":1024}
		},
		"delivery":{"callback_url":"https://example.com/callback"}
	}`

	req, err := DecodeAudioCreate(strings.NewReader(body))
	if err != nil {
		t.Fatalf("DecodeAudioCreate: %v", err)
	}
	if req.Type != queue.TypeAudioTranscode {
		t.Fatalf("type = %q, want %q", req.Type, queue.TypeAudioTranscode)
	}
	if req.Hash != "hash123" || req.Source != "uploads/audio.flac" {
		t.Fatalf("unexpected request: %+v", req)
	}
	if req.Options["hls"] != true || req.Options["mp3"] != true || req.Options["waveform"] != true {
		t.Fatalf("unexpected options: %#v", req.Options)
	}
}

func TestDecodeAudioCreateRejectsStructuredJobDiscriminatorFields(t *testing.T) {
	body := `{
		"asset_type":"audio",
		"operation":"process",
		"source":{"hash":"hash123","key":"uploads/audio.flac"}
	}`

	_, err := DecodeAudioCreate(strings.NewReader(body))
	if err == nil {
		t.Fatal("expected discriminator fields to be rejected")
	}
	if !strings.Contains(err.Error(), "/api/audio/jobs contract") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDecodeImageCreate(t *testing.T) {
	body := `{
		"source":{"hash":"hash123","key":"uploads/image.png"},
		"pipeline":{"outputs":[{"variant":"thumbnail","width":320,"format":"webp"}]},
		"delivery":{"callback_url":"https://example.com/callback"}
	}`

	req, err := DecodeImageCreate(strings.NewReader(body))
	if err != nil {
		t.Fatalf("DecodeImageCreate: %v", err)
	}
	if req.Type != queue.TypeImageThumbnail {
		t.Fatalf("type = %q, want %q", req.Type, queue.TypeImageThumbnail)
	}
	if req.Hash != "hash123" || req.Source != "uploads/image.png" {
		t.Fatalf("unexpected request: %+v", req)
	}
	outputs, ok := req.Options["outputs"].([]map[string]any)
	if !ok || len(outputs) != 1 || outputs[0]["variant"] != "thumbnail" {
		t.Fatalf("unexpected options: %#v", req.Options)
	}
	if req.CallbackURL != "https://example.com/callback" {
		t.Fatalf("callback_url = %q", req.CallbackURL)
	}
}

func TestDecodeImageCreateRejectsStructuredJobDiscriminatorFields(t *testing.T) {
	body := `{
		"asset_type":"image",
		"operation":"process",
		"source":{"hash":"hash123","key":"uploads/image.png"}
	}`

	_, err := DecodeImageCreate(strings.NewReader(body))
	if err == nil {
		t.Fatal("expected discriminator fields to be rejected")
	}
	if !strings.Contains(err.Error(), `unknown field "asset_type"`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDecodeImageCreateRejectsForbiddenFieldsRegardlessOfValue(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "empty asset type", body: `{"asset_type":"","source":{"hash":"hash123","key":"uploads/image.png"}}`},
		{name: "empty operation", body: `{"operation":"","source":{"hash":"hash123","key":"uploads/image.png"}}`},
		{name: "empty legacy type", body: `{"type":"","source":{"hash":"hash123","key":"uploads/image.png"}}`},
		{name: "empty legacy hash", body: `{"hash":"","source":{"hash":"hash123","key":"uploads/image.png"}}`},
		{name: "null legacy options", body: `{"options":null,"source":{"hash":"hash123","key":"uploads/image.png"}}`},
		{name: "empty legacy callback", body: `{"callback_url":"","source":{"hash":"hash123","key":"uploads/image.png"}}`},
		{name: "disabled analyze", body: `{"source":{"hash":"hash123","key":"uploads/image.png"},"pipeline":{"analyze":false}}`},
		{name: "empty downloads", body: `{"source":{"hash":"hash123","key":"uploads/image.png"},"pipeline":{"downloads":[]}}`},
		{name: "disabled waveform", body: `{"source":{"hash":"hash123","key":"uploads/image.png"},"pipeline":{"waveform":{"enabled":false}}}`},
		{name: "disabled normalize", body: `{"source":{"hash":"hash123","key":"uploads/image.png"},"pipeline":{"normalize":{"enabled":false}}}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeImageCreate(strings.NewReader(tt.body))
			if err == nil {
				t.Fatal("expected forbidden field to be rejected")
			}
			if !strings.Contains(err.Error(), "unknown field") {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestDecodeImageCreateCanonicalizesOutputFormat(t *testing.T) {
	body := `{
		"source":{"hash":"hash123","key":"uploads/image.png"},
		"pipeline":{"outputs":[{"variant":" thumbnail ","width":320,"format":" .JPEG "}]}
	}`

	req, err := DecodeImageCreate(strings.NewReader(body))
	if err != nil {
		t.Fatalf("DecodeImageCreate: %v", err)
	}
	outputs, ok := req.Options["outputs"].([]map[string]any)
	if !ok || len(outputs) != 1 {
		t.Fatalf("unexpected options: %#v", req.Options)
	}
	if outputs[0]["variant"] != "thumbnail" || outputs[0]["format"] != "jpg" {
		t.Fatalf("output was not canonicalized: %#v", outputs[0])
	}
}

func TestDecodeImageCreateRejectsUnsupportedOutputFormat(t *testing.T) {
	body := `{
		"source":{"hash":"hash123","key":"uploads/image.png"},
		"pipeline":{"outputs":[{"variant":"thumbnail","width":320,"format":"not-a-format"}]}
	}`

	_, err := DecodeImageCreate(strings.NewReader(body))
	if err == nil {
		t.Fatal("expected unsupported format to be rejected")
	}
	if !strings.Contains(err.Error(), "unsupported format") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDecodeVideoCreate(t *testing.T) {
	body := `{
		"source":{"hash":"hash123","key":"uploads/video.mp4"},
		"pipeline":{"package":{"hls":{"enabled":true,"profile":"stream_video_standard","encryption":{"enabled":true}}}},
		"delivery":{"callback_url":"https://example.com/callback"}
	}`

	req, err := DecodeVideoCreate(strings.NewReader(body))
	if err != nil {
		t.Fatalf("DecodeVideoCreate: %v", err)
	}
	if req.Type != queue.TypeVideoTranscode {
		t.Fatalf("type = %q, want %q", req.Type, queue.TypeVideoTranscode)
	}
	if req.Hash != "hash123" || req.Source != "uploads/video.mp4" {
		t.Fatalf("unexpected request: %+v", req)
	}
	if req.Options["encrypt"] != true {
		t.Fatalf("unexpected options: %#v", req.Options)
	}
}

func TestDecodeVideoCreateRejectsStructuredJobDiscriminatorFields(t *testing.T) {
	body := `{
		"asset_type":"video",
		"operation":"process",
		"source":{"hash":"hash123","key":"uploads/video.mp4"}
	}`

	_, err := DecodeVideoCreate(strings.NewReader(body))
	if err == nil {
		t.Fatal("expected discriminator fields to be rejected")
	}
	if !strings.Contains(err.Error(), "/api/video/jobs contract") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRejectsBadCallbackURL(t *testing.T) {
	err := Validate(Normalized{
		Type:        queue.TypeAudioTranscode,
		Hash:        "hash123",
		Source:      "uploads/audio.flac",
		CallbackURL: "ftp://example.com/callback",
	})
	if err == nil {
		t.Fatal("expected invalid callback URL to be rejected")
	}
	if !strings.Contains(err.Error(), "callback_url must use http:// or https://") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCanonicalizeAudioTranscodeDefaultsOutputs(t *testing.T) {
	req := Normalized{
		Type:   queue.TypeAudioTranscode,
		Hash:   "hash123",
		Source: "uploads/audio.flac",
	}

	if err := Canonicalize(&req); err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	if req.Options["hls"] != true || req.Options["mp3"] != true || req.Options["flac"] != true || req.Options["waveform"] != true {
		t.Fatalf("expected default outputs to be enabled, got %#v", req.Options)
	}
	if req.Options["mp3_bitrate"] != "320k" {
		t.Fatalf("expected default mp3 bitrate 320k, got %#v", req.Options["mp3_bitrate"])
	}
	if req.Options["waveform_bins"] != float64(2048) {
		t.Fatalf("expected default waveform bins 2048, got %#v", req.Options["waveform_bins"])
	}
}

func TestCanonicalizeImageThumbnailPreservesOutputs(t *testing.T) {
	req := Normalized{
		Type:   queue.TypeImageThumbnail,
		Hash:   "hash123",
		Source: "uploads/image.png",
		Options: map[string]any{
			"outputs": []map[string]any{{
				"variant": "thumbnail",
				"width":   320,
				"height":  180,
				"format":  "webp",
			}},
		},
	}

	if err := Canonicalize(&req); err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	parsed, err := parseImageThumbnailOptions(req.Options)
	if err != nil {
		t.Fatalf("parseImageThumbnailOptions: %v", err)
	}
	if len(parsed.Outputs) != 1 {
		t.Fatalf("outputs length = %d, want 1", len(parsed.Outputs))
	}
	want := queue.ThumbnailOutput{Variant: "thumbnail", Width: 320, Height: 180, Format: "webp"}
	if parsed.Outputs[0] != want {
		t.Fatalf("output = %#v, want %#v", parsed.Outputs[0], want)
	}
	if _, ok := req.Options["outputs"].([]any); !ok {
		t.Fatalf("canonical outputs type = %T, want []any", req.Options["outputs"])
	}
}

func TestCanonicalizeImageThumbnailNormalizesEquivalentFormats(t *testing.T) {
	for _, format := range []string{"jpg", "jpeg", "JPG", ".JPEG"} {
		t.Run(format, func(t *testing.T) {
			req := Normalized{
				Type:   queue.TypeImageThumbnail,
				Hash:   "hash123",
				Source: "uploads/image.png",
				Options: map[string]any{
					"outputs": []map[string]any{{
						"variant": "thumbnail",
						"width":   320,
						"format":  format,
					}},
				},
			}

			if err := Canonicalize(&req); err != nil {
				t.Fatalf("Canonicalize: %v", err)
			}
			parsed, err := parseImageThumbnailOptions(req.Options)
			if err != nil {
				t.Fatalf("parseImageThumbnailOptions: %v", err)
			}
			if parsed.Outputs[0].Format != "jpg" {
				t.Fatalf("format = %q, want jpg", parsed.Outputs[0].Format)
			}
		})
	}
}

func TestCanonicalizeImageThumbnailRejectsUnsupportedFormat(t *testing.T) {
	req := Normalized{
		Type:   queue.TypeImageThumbnail,
		Hash:   "hash123",
		Source: "uploads/image.png",
		Options: map[string]any{
			"outputs": []map[string]any{{
				"variant": "thumbnail",
				"width":   320,
				"format":  "not-a-format",
			}},
		},
	}

	err := Canonicalize(&req)
	if err == nil {
		t.Fatal("expected unsupported format to be rejected")
	}
	if !strings.Contains(err.Error(), "unsupported format") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCanonicalizeVideoFullDropsEmptyStages(t *testing.T) {
	req := Normalized{
		Type:   queue.TypeVideoFull,
		Hash:   "hash123",
		Source: "uploads/video.mp4",
		Options: map[string]any{
			"cover":     map[string]any{},
			"preview":   map[string]any{},
			"transcode": map[string]any{},
		},
	}

	if err := Canonicalize(&req); err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	if len(req.Options) != 0 {
		t.Fatalf("expected empty options after canonicalization, got %#v", req.Options)
	}
}

func TestDecodeRejectsMixedStructuredAndDeprecatedFields(t *testing.T) {
	body := `{
		"type":"audio:transcode",
		"asset_type":"audio",
		"operation":"process",
		"source":{"hash":"hash123","key":"uploads/audio.flac"}
	}`

	_, err := Decode(strings.NewReader(body))
	if err == nil {
		t.Fatal("expected mixed structured and deprecated fields to be rejected")
	}
	if !strings.Contains(err.Error(), "structured requests cannot include type/hash/options/callback_url fields") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDecodeRejectsUnstructuredRequest(t *testing.T) {
	body := `{
		"type":"audio:transcode",
		"hash":"hash123",
		"source":"uploads/audio.flac"
	}`

	_, err := Decode(strings.NewReader(body))
	if err == nil {
		t.Fatal("expected unstructured request to be rejected")
	}
	if !strings.Contains(err.Error(), "job requests must use the structured asset_type/operation contract") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDecodeStructuredAudioProcessDownloadProfiles(t *testing.T) {
	body := `{
		"asset_type":"audio",
		"operation":"process",
		"source":{"hash":"hash123","key":"uploads/audio.flac"},
		"pipeline":{
			"downloads":[
				{"profile":"download_mp3_high"},
				{"profile":"download_flac_standard"}
			]
		}
	}`

	req, err := Decode(strings.NewReader(body))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if req.Options["mp3"] != true || req.Options["flac"] != true {
		t.Fatalf("unexpected options: %#v", req.Options)
	}
	if req.Options["mp3_bitrate"] != "320k" {
		t.Fatalf("expected profile bitrate 320k, got %#v", req.Options["mp3_bitrate"])
	}
}

func TestDecodeStructuredAudioProcessRejectsUnsupportedFlacProfileName(t *testing.T) {
	body := `{
		"asset_type":"audio",
		"operation":"process",
		"source":{"hash":"hash123","key":"uploads/audio.flac"},
		"pipeline":{
			"downloads":[{"profile":"download_flac_lossless"}]
		}
	}`

	_, err := Decode(strings.NewReader(body))
	if err == nil {
		t.Fatal("expected unsupported flac profile name to be rejected")
	}
	if !strings.Contains(err.Error(), "unsupported pipeline.downloads profile") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDecodeStructuredAudioProcessRejectsUnknownWaveformProfile(t *testing.T) {
	body := `{
		"asset_type":"audio",
		"operation":"process",
		"source":{"hash":"hash123","key":"uploads/audio.flac"},
		"pipeline":{
			"waveform":{"enabled":true,"profile":"custom_waveform"}
		}
	}`

	_, err := Decode(strings.NewReader(body))
	if err == nil {
		t.Fatal("expected unknown waveform profile to be rejected")
	}
	if !strings.Contains(err.Error(), "unsupported pipeline.waveform.profile") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDecodeStructuredAudioProcessRejectsProfileFormatConflict(t *testing.T) {
	body := `{
		"asset_type":"audio",
		"operation":"process",
		"source":{"hash":"hash123","key":"uploads/audio.flac"},
		"pipeline":{
			"downloads":[{"profile":"download_mp3_high","format":"flac"}]
		}
	}`

	_, err := Decode(strings.NewReader(body))
	if err == nil {
		t.Fatal("expected profile/format conflict to be rejected")
	}
	if !strings.Contains(err.Error(), "conflicts with format") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDecodeStructuredVideoProcessDefaultsToVideoFull(t *testing.T) {
	body := `{
		"asset_type":"video",
		"operation":"process",
		"source":{"hash":"hash123","key":"uploads/video.mp4"}
	}`

	req, err := Decode(strings.NewReader(body))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if req.Type != queue.TypeVideoFull {
		t.Fatalf("type = %q, want %q", req.Type, queue.TypeVideoFull)
	}
	if len(req.Options) != 0 {
		t.Fatalf("expected empty default options, got %#v", req.Options)
	}
}

func TestDecodeStructuredVideoProcessHLSPackageOnly(t *testing.T) {
	body := `{
		"asset_type":"video",
		"operation":"process",
		"source":{"hash":"hash123","key":"uploads/video.mp4"},
		"pipeline":{"package":{"hls":{"enabled":true,"profile":"stream_video_standard","encryption":{"enabled":true}}}}
	}`

	req, err := Decode(strings.NewReader(body))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if req.Type != queue.TypeVideoTranscode {
		t.Fatalf("type = %q, want %q", req.Type, queue.TypeVideoTranscode)
	}
	if req.Options["encrypt"] != true {
		t.Fatalf("unexpected options: %#v", req.Options)
	}
}

func TestDecodeStructuredVideoProcessRejectsUnsupportedDeliverableCombination(t *testing.T) {
	body := `{
		"asset_type":"video",
		"operation":"process",
		"source":{"hash":"hash123","key":"uploads/video.mp4"},
		"pipeline":{"cover":{"enabled":true},"package":{"hls":{"enabled":true}}}
	}`

	_, err := Decode(strings.NewReader(body))
	if err == nil {
		t.Fatal("expected unsupported deliverable combination error")
	}
	if !strings.Contains(err.Error(), "supported combinations are cover only, preview only, package.hls only, or cover+preview+package.hls") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDecodeStructuredVideoProcessRejectsTranscodeField(t *testing.T) {
	body := `{
		"asset_type":"video",
		"operation":"process",
		"source":{"hash":"hash123","key":"uploads/video.mp4"},
		"pipeline":{"transcode":{"enabled":true,"encrypt":true}}
	}`

	_, err := Decode(strings.NewReader(body))
	if err == nil {
		t.Fatal("expected transcode field to be rejected")
	}
	if !strings.Contains(err.Error(), "pipeline.transcode is not part of the public contract") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDecodeStructuredImageProcessMapsToImageThumbnail(t *testing.T) {
	body := `{
		"asset_type":"image",
		"operation":"process",
		"source":{"hash":"hash123","key":"uploads/image.png"},
		"pipeline":{
			"outputs":[
				{"variant":"thumb","width":320,"format":"webp"},
				{"variant":"large","width":1280,"height":720,"format":"avif"}
			]
		}
	}`

	req, err := Decode(strings.NewReader(body))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if req.Type != queue.TypeImageThumbnail {
		t.Fatalf("type = %q, want %q", req.Type, queue.TypeImageThumbnail)
	}
	outputs, ok := req.Options["outputs"].([]map[string]any)
	if !ok {
		t.Fatalf("outputs type = %T, want []map[string]any", req.Options["outputs"])
	}
	if len(outputs) != 2 {
		t.Fatalf("output count = %d, want 2", len(outputs))
	}
	if outputs[0]["variant"] != "thumb" || outputs[0]["width"] != 320 || outputs[0]["format"] != "webp" {
		t.Fatalf("unexpected first output: %#v", outputs[0])
	}
	if outputs[1]["height"] != 720 {
		t.Fatalf("unexpected second output: %#v", outputs[1])
	}
}

func TestDecodeStructuredImageProcessRejectsDownloads(t *testing.T) {
	body := `{
		"asset_type":"image",
		"operation":"process",
		"source":{"hash":"hash123","key":"uploads/image.png"},
		"pipeline":{
			"downloads":[{"format":"png"}]
		}
	}`

	_, err := Decode(strings.NewReader(body))
	if err == nil {
		t.Fatal("expected unsupported image downloads error")
	}
	if !strings.Contains(err.Error(), "image pipeline: downloads") {
		t.Fatalf("unexpected error: %v", err)
	}
}
