-- CP-COMPLIANCE-REC-1: real, general "this call may be recorded" consent-announcement audio,
-- recordable/uploadable from the console instead of needing an engineer to hand-produce a .wav
-- (the real, named gap CAREPYRE-9311 left open: "the announcement .wav doesn't exist in this
-- repo yet"). Single-row table (id fixed at 1) -- one active announcement per instance, same
-- idiom branding_settings above already uses. audio_data holds the raw uploaded bytes (whatever
-- the browser's MediaRecorder produced, usually audio/webm;codecs=opus) -- converting that to a
-- telephony-ready format (8kHz mono WAV/ulaw) for Asterisk's own Playback() is a real, separate,
-- deliberately-not-automatic step (see sudo-queue's own compliance-recording-deploy script),
-- since it touches the live PBX's sounds directory.
CREATE TABLE IF NOT EXISTS compliance_recordings (
    id           INTEGER      PRIMARY KEY CHECK (id = 1),
    content_type VARCHAR(64)  NOT NULL,
    audio_data   BLOB         NOT NULL,
    uploaded_by  INTEGER      NOT NULL,
    updated_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
);
