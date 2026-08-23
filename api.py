from http.server import BaseHTTPRequestHandler
import json
import re
import unicodedata
import hashlib
from datetime import datetime, timezone, timedelta

# --- CRC32C Table (Castagnoli 0x82F63B78 reflected) ---
CRC32C_TABLE = []
for i in range(256):
    c = i
    for _ in range(8):
        c = (0x82F63B78 ^ (c >> 1)) if (c & 1) else (c >> 1)
    CRC32C_TABLE.append(c & 0xFFFFFFFF)

def compute_crc32c(data: bytes) -> str:
    crc = 0xFFFFFFFF
    for b in data:
        crc = (CRC32C_TABLE[(crc ^ b) & 0xFF] ^ (crc >> 8)) & 0xFFFFFFFF
    return f"{crc ^ 0xFFFFFFFF:08x}"

# --- UTF-8 Byte Comparison ---
def utf8_cmp(a, b):
    if a is None and b is None:
        return 0
    if a is None:
        return -1
    if b is None:
        return 1
    ba = a.encode("utf-8")
    bb = b.encode("utf-8")
    return (ba > bb) - (ba < bb)

class Utf8SortKey:
    def __init__(self, obj):
        self.obj = obj
    def __lt__(self, other):
        return utf8_cmp(self.obj, other.obj) < 0
    def __gt__(self, other):
        return utf8_cmp(self.obj, other.obj) > 0
    def __eq__(self, other):
        return utf8_cmp(self.obj, other.obj) == 0

# --- ISO 8601 Timestamp Validation & UTC Normalization ---
TS_REGEX = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?(Z|[+-]\d{2}:\d{2})$")

def parse_and_normalize_timestamp(ts_str):
    if not isinstance(ts_str, str):
        return False, None, None
    m = TS_REGEX.match(ts_str)
    if not m:
        return False, None, None
    
    y, mon, d, h, mi, s, frac, tz = m.groups()
    y, mon, d, h, mi, s = int(y), int(mon), int(d), int(h), int(mi), int(s)
    ms = int(frac.ljust(3, '0')) if frac else 0

    if not (1 <= mon <= 12 and 0 <= h <= 23 and 0 <= mi <= 59 and 0 <= s <= 59):
        return False, None, None
    
    try:
        if tz == "Z":
            tz_obj = timezone.utc
        else:
            sign = -1 if tz[0] == '-' else 1
            tz_h = int(tz[1:3])
            tz_m = int(tz[4:6])
            if tz_h > 14 or (tz_h == 14 and tz_m != 0) or tz_m > 59:
                return False, None, None
            tz_obj = timezone(sign * timedelta(hours=tz_h, minutes=tz_m))
        
        dt = datetime(y, mon, d, h, mi, s, ms * 1000, tzinfo=tz_obj)
        utc_dt = dt.astimezone(timezone.utc)
        normalized = utc_dt.strftime("%Y-%m-%dT%H:%M:%S") + f".{utc_dt.microsecond // 1000:03d}Z"
        return True, normalized, utc_dt.timestamp()
    except Exception:
        return False, None, None

# --- Canonicalization & Similarity ---
def canonicalize_text(text: str) -> str:
    nfkc = unicodedata.normalize("NFKC", text).lower()
    return re.sub(r"\s+", " ", nfkc).strip()

def extract_word_set(text: str) -> set:
    words = re.findall(r"[\w]+", text)
    return set(w.lower() for w in words)

def jaccard(set_a: set, set_b: set) -> float:
    if not set_a and not set_b:
        return 1.0
    union = len(set_a | set_b)
    if union == 0:
        return 1.0
    return len(set_a & set_b) / union

def row_compact_json(row_dict):
    ordered = {
        "id": row_dict["id"],
        "entity": row_dict["entity"],
        "eventTime": row_dict["eventTime"],
        "revision": row_dict["revision"],
        "text": row_dict["text"]
    }
    return json.dumps(ordered, separators=(',', ':'), ensure_ascii=False)

# --- Serverless Handler ---
class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/build-corpus":
            self.send_response(404)
            self.end_headers()
            return

        content_len = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_len)

        try:
            body = json.loads(post_data.decode("utf-8"))
        except Exception:
            self.send_error_response(400, {"error": "INVALID_INPUT"})
            return

        if not isinstance(body, dict) or "policy" not in body or not isinstance(body.get("objects"), list):
            self.send_error_response(400, {"error": "INVALID_INPUT"})
            return

        policy = body.get("policy")
        objects = body.get("objects")

        # Validate Policy
        policy_valid = True
        min_ts = -float("inf")
        max_ts = float("inf")
        contamination_threshold = 0.8

        if not isinstance(policy, dict):
            policy_valid = False
        else:
            p_min_valid, _, p_min_val = parse_and_normalize_timestamp(policy.get("minTime"))
            p_max_valid, _, p_max_val = parse_and_normalize_timestamp(policy.get("maxTime"))
            thresh = policy.get("contaminationThreshold")

            if (not p_min_valid or not p_max_valid or not isinstance(thresh, (int, float)) or
                isinstance(thresh, bool) or thresh < 0 or thresh > 1 or p_min_val > p_max_val):
                policy_valid = False
            else:
                min_ts = p_min_val
                max_ts = p_max_val
                contamination_threshold = float(thresh)

        rejected_objects = []
        valid_objects = []
        all_parsed_rows = []

        # Process Input Objects
        for obj in objects:
            codes = set()
            uri = obj.get("uri") if isinstance(obj, dict) and isinstance(obj.get("uri"), str) else None

            if not isinstance(obj, dict):
                rejected_objects.append({"uri": None, "reasonCodes": ["SCHEMA_INVALID"]})
                continue

            if not isinstance(obj.get("uri"), str) or not re.match(r"^gs://[^/\s]+/.+$", obj["uri"]):
                codes.add("URI_INVALID")

            gen = obj.get("generation")
            f_gen = obj.get("fetchedGeneration")
            gen_dec = isinstance(gen, str) and gen.isdigit()
            f_gen_dec = isinstance(f_gen, str) and f_gen.isdigit()

            if not gen_dec or not f_gen_dec:
                codes.add("GENERATION_INVALID")
            if gen != f_gen:
                codes.add("GENERATION_MISMATCH")

            crc = obj.get("crc32c")
            valid_crc_syntax = isinstance(crc, str) and bool(re.match(r"^[0-9a-f]{8}$", crc))
            if not valid_crc_syntax:
                codes.add("CRC32C_INVALID")

            content = obj.get("content")
            if not isinstance(content, str):
                codes.add("SCHEMA_INVALID")
            elif valid_crc_syntax:
                computed_crc = compute_crc32c(content.encode("utf-8"))
                if computed_crc != crc:
                    codes.add("CRC32C_MISMATCH")

            if obj.get("schemaId") != "training-v1":
                codes.add("SCHEMA_INVALID")

            object_rows = []
            if isinstance(content, str):
                lines = [line for line in content.split("\n") if line.strip() != ""]
                if len(lines) == 0:
                    codes.add("SCHEMA_INVALID")
                else:
                    for line in lines:
                        try:
                            parsed_row = json.loads(line)
                        except Exception:
                            codes.add("JSONL_INVALID")
                            continue

                        if (not isinstance(parsed_row, dict) or len(parsed_row) != 5 or
                            not all(k in parsed_row for k in ["id", "entity", "eventTime", "revision", "text"]) or
                            not isinstance(parsed_row["id"], str) or
                            not isinstance(parsed_row["entity"], str) or
                            not isinstance(parsed_row["eventTime"], str) or
                            not isinstance(parsed_row["text"], str) or
                            not isinstance(parsed_row["revision"], int) or
                            isinstance(parsed_row["revision"], bool) or
                            parsed_row["revision"] < 0 or
                            parsed_row["revision"] > (2**53 - 1)):
                            codes.add("SCHEMA_INVALID")
                            continue

                        ts_valid, norm_time, epoch_ts = parse_and_normalize_timestamp(parsed_row["eventTime"])
                        if not ts_valid:
                            codes.add("SCHEMA_INVALID")
                            continue

                        object_rows.append({
                            "id": parsed_row["id"],
                            "entity": canonicalize_text(parsed_row["entity"]),
                            "eventTime": norm_time,
                            "time_ts": epoch_ts,
                            "revision": parsed_row["revision"],
                            "text": canonicalize_text(parsed_row["text"])
                        })

            if codes:
                rejected_objects.append({
                    "uri": uri,
                    "reasonCodes": sorted(list(codes), key=Utf8SortKey)
                })
            else:
                valid_objects.append(obj)
                all_parsed_rows.extend(object_rows)

        # Deduplication
        dedup_groups = {}
        for row in all_parsed_rows:
            key = (row["entity"], row["eventTime"], row["text"])
            dedup_groups.setdefault(key, []).append(row)

        retained_rows = []
        rejected_rows_dict = {}

        def reject_row(row_id, reason):
            if row_id not in rejected_rows_dict:
                rejected_rows_dict[row_id] = set()
            rejected_rows_dict[row_id].add(reason)

        for _, group in dedup_groups.items():
            group.sort(key=lambda r: (-r["revision"], Utf8SortKey(r["id"])))
            winner = group[0]
            retained_rows.append(winner)
            for loser in group[1:]:
                reject_row(loser["id"], "DUPLICATE")

        # Policy & Window Filtering
        candidate_rows = []
        for row in retained_rows:
            if not policy_valid:
                reject_row(row["id"], "POLICY_INVALID")
            elif not (min_ts <= row["time_ts"] <= max_ts):
                reject_row(row["id"], "OUT_OF_WINDOW")
            else:
                candidate_rows.append(row)

        # Split Assignment
        train_cand = []
        val_cand = []
        test_cand = []

        for row in candidate_rows:
            e_hash = hashlib.sha256(row["entity"].encode("utf-8")).digest()
            bucket = e_hash[0] % 10
            if 0 <= bucket <= 5:
                train_cand.append(row)
            elif 6 <= bucket <= 7:
                val_cand.append(row)
            else:
                test_cand.append(row)

        # Contamination Filtering
        train_word_sets = [extract_word_set(r["text"]) for r in train_cand]

        def is_contaminated(row):
            wset = extract_word_set(row["text"])
            for tset in train_word_sets:
                if jaccard(wset, tset) >= contamination_threshold:
                    return True
            return False

        final_train = list(train_cand)
        final_val = []
        final_test = []

        for row in val_cand:
            if is_contaminated(row):
                reject_row(row["id"], "TRAIN_CONTAMINATION")
            else:
                final_val.append(row)

        for row in test_cand:
            if is_contaminated(row):
                reject_row(row["id"], "TRAIN_CONTAMINATION")
            else:
                final_test.append(row)

        # Artifact Serialization & Digest Computation
        def process_split_rows(rows):
            rows.sort(key=lambda r: (Utf8SortKey(r["id"]), Utf8SortKey(row_compact_json(r))))
            formatted = [{
                "id": r["id"],
                "entity": r["entity"],
                "eventTime": r["eventTime"],
                "revision": r["revision"],
                "text": r["text"]
            } for r in rows]

            if formatted:
                lines = [json.dumps(r, separators=(',', ':'), ensure_ascii=False) for r in formatted]
                content_bytes = ("\n".join(lines) + "\n").encode("utf-8")
            else:
                content_bytes = b""

            digest = hashlib.sha256(content_bytes).hexdigest()
            return formatted, digest

        train_rows, train_digest = process_split_rows(final_train)
        val_rows, val_digest = process_split_rows(final_val)
        test_rows, test_digest = process_split_rows(final_test)

        # Sort Final Results
        rejected_objects.sort(key=lambda o: (
            Utf8SortKey(o["uri"]),
            Utf8SortKey(json.dumps(o, separators=(',', ':'), ensure_ascii=False))
        ))

        rejected_rows = [
            {"id": r_id, "reasonCodes": sorted(list(reasons), key=Utf8SortKey)}
            for r_id, reasons in rejected_rows_dict.items()
        ]
        rejected_rows.sort(key=lambda r: (
            Utf8SortKey(r["id"]),
            Utf8SortKey(json.dumps(r, separators=(',', ':'), ensure_ascii=False))
        ))

        lineage = [{
            "uri": obj["uri"],
            "generation": obj["generation"],
            "crc32c": obj["crc32c"],
            "schemaId": obj["schemaId"]
        } for obj in valid_objects]

        lineage.sort(key=lambda item: (
            Utf8SortKey(item["uri"]),
            Utf8SortKey(json.dumps(item, separators=(',', ':'), ensure_ascii=False))
        ))

        response_payload = {
            "splits": {
                "train": train_rows,
                "validation": val_rows,
                "test": test_rows
            },
            "rejectedObjects": rejected_objects,
            "rejectedRows": rejected_rows,
            "digests": {
                "train": train_digest,
                "validation": val_digest,
                "test": test_digest
            },
            "lineage": lineage
        }

        self.send_json_response(200, response_payload)

    def send_error_response(self, code, payload):
        self.send_json_response(code, payload)

    def send_json_response(self, code, payload):
        body_bytes = json.dumps(payload, separators=(',', ':'), ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body_bytes)))
        self.end_headers()
        self.wfile.write(body_bytes)