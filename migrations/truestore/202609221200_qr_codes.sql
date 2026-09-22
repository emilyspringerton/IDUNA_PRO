-- Dynamic QR code registry, ported from IDUNA (founder real-time: "in carepyre if there is a
-- resume configured can we generate some business card tools powered by the qr code stuff port
-- it to IDUNAPRO"). Field-for-field identical to IDUNA's own qr_codes table
-- (IDUNA/migrations/truestore/202609221040_qr_codes.sql) -- same real reasoning: the QR image
-- only ever encodes THIS server's own redirect URL (BASE_URL + "/q/" + slug), never the real
-- destination directly, so retargeting a code (PATCH) repoints every already-printed copy
-- instantly with zero reprinting. Real, new consumer here: CarePyre's Community Tools business-
-- card generator creates one QR code per user (slug "card-<uid>") pointing at that user's own
-- real /card/{uid}.vcf endpoint.
CREATE TABLE IF NOT EXISTS qr_codes (
    id           INTEGER  PRIMARY KEY AUTOINCREMENT,
    slug         VARCHAR(64)   NOT NULL,
    target_url   VARCHAR(2000) NOT NULL,
    label        VARCHAR(200)  NOT NULL DEFAULT '',
    hit_count    INTEGER  NOT NULL DEFAULT 0,
    created_by   VARCHAR(100)  NOT NULL DEFAULT '',
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_qr_codes_slug ON qr_codes(slug);
