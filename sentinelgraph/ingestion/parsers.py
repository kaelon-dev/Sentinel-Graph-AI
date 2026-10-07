"""Parsers for CSV, JSON, and JSON Lines logs with duplicate detection and provenance tracking."""
import csv
import io
import json
import uuid
from pathlib import Path
from typing import List, Tuple, Union
from sentinelgraph.models import NormalizedEvent, InvalidEventRecord, SourceFileMetadata
from sentinelgraph.ingestion.integrity import generate_source_metadata
from sentinelgraph.ingestion.normalizer import normalize_record


class LogParser:
    """Unified log ingestion parser supporting CSV, JSON, and JSON Lines."""

    @staticmethod
    def parse_content(
        content: Union[str, bytes],
        file_name: str,
        run_id: str = ""
    ) -> Tuple[List[NormalizedEvent], List[InvalidEventRecord], int, SourceFileMetadata]:
        """Parse raw file content string or bytes into validated normalized events."""
        if not run_id:
            run_id = f"RUN-{uuid.uuid4().hex[:8].upper()}"

        if isinstance(content, str):
            content_bytes = content.encode("utf-8")
            content_str = content
        else:
            content_bytes = content
            content_str = content.decode("utf-8", errors="replace")

        source_meta = generate_source_metadata(
            file_name=file_name,
            content_bytes=content_bytes,
            run_id=run_id
        )

        ext = Path(file_name).suffix.lower()
        if ext == ".csv":
            raw_records, parse_invalids = LogParser._parse_csv(content_str, file_name)
        elif ext == ".jsonl":
            raw_records, parse_invalids = LogParser._parse_jsonl(content_str, file_name)
        elif ext == ".json":
            raw_records, parse_invalids = LogParser._parse_json(content_str, file_name)
        else:
            # Try JSON first, fallback to CSV
            try:
                raw_records, parse_invalids = LogParser._parse_json(content_str, file_name)
            except Exception:
                raw_records, parse_invalids = LogParser._parse_csv(content_str, file_name)

        valid_events: List[NormalizedEvent] = []
        invalid_records: List[InvalidEventRecord] = list(parse_invalids)
        seen_event_ids = set()
        seen_fingerprints = set()
        duplicate_count = 0

        for row_num, raw in raw_records:
            if not isinstance(raw, dict):
                invalid_records.append(
                    InvalidEventRecord(
                        source_file=file_name,
                        row_number=row_num,
                        raw_record=raw,
                        validation_error="Record is not a JSON/dictionary object",
                        reason="Expected key-value record mapping"
                    )
                )
                continue

            event, invalid = normalize_record(raw, row_num=row_num, source_file=file_name)
            if invalid:
                invalid_records.append(invalid)
                continue

            if event:
                # Duplicate check
                if event.event_id in seen_event_ids or event.event_fingerprint in seen_fingerprints:
                    duplicate_count += 1
                    continue

                seen_event_ids.add(event.event_id)
                seen_fingerprints.add(event.event_fingerprint)
                valid_events.append(event)

        # Sort chronologically by UTC timestamp, tiebreaking on event_id for determinism
        valid_events.sort(key=lambda e: (e.timestamp, e.event_id))

        return valid_events, invalid_records, duplicate_count, source_meta

    @staticmethod
    def parse_file(
        file_path: Union[str, Path],
        run_id: str = ""
    ) -> Tuple[List[NormalizedEvent], List[InvalidEventRecord], int, SourceFileMetadata]:
        """Convenience method to parse a local file from disk."""
        p = Path(file_path)
        with open(p, "rb") as f:
            content_bytes = f.read()
        return LogParser.parse_content(content=content_bytes, file_name=p.name, run_id=run_id)

    @staticmethod
    def _parse_csv(content_str: str, file_name: str) -> Tuple[List[Tuple[int, dict]], List[InvalidEventRecord]]:
        records = []
        invalids = []
        reader = csv.reader(io.StringIO(content_str))
        headers = None
        
        for idx, row in enumerate(reader, start=1):
            if not row or all(c.strip() == "" for c in row):
                continue
            if headers is None:
                headers = [h.strip() for h in row]
                continue
            if len(row) != len(headers):
                invalids.append(
                    InvalidEventRecord(
                        source_file=file_name,
                        row_number=idx,
                        raw_record=",".join(row),
                        validation_error=f"Column count mismatch: expected {len(headers)}, got {len(row)}",
                        reason="CSV row field count differs from header"
                    )
                )
                continue
            record = dict(zip(headers, row))
            records.append((idx, record))
            
        return records, invalids

    @staticmethod
    def _parse_json(content_str: str, file_name: str) -> Tuple[List[Tuple[int, dict]], List[InvalidEventRecord]]:
        records = []
        invalids = []
        try:
            data = json.loads(content_str)
        except Exception as e:
            invalids.append(
                InvalidEventRecord(
                    source_file=file_name,
                    row_number=1,
                    raw_record=content_str[:500],
                    validation_error=str(e),
                    reason="Invalid JSON syntax"
                )
            )
            return records, invalids

        if isinstance(data, list):
            for idx, item in enumerate(data, start=1):
                records.append((idx, item))
        elif isinstance(data, dict):
            # Check for events array or single record
            events_list = data.get("events") or data.get("logs") or data.get("records")
            if isinstance(events_list, list):
                for idx, item in enumerate(events_list, start=1):
                    records.append((idx, item))
            else:
                records.append((1, data))
        else:
            invalids.append(
                InvalidEventRecord(
                    source_file=file_name,
                    row_number=1,
                    raw_record=str(data)[:500],
                    validation_error="Top level JSON must be a list or object",
                    reason="Unexpected JSON root structure"
                )
            )

        return records, invalids

    @staticmethod
    def _parse_jsonl(content_str: str, file_name: str) -> Tuple[List[Tuple[int, dict]], List[InvalidEventRecord]]:
        records = []
        invalids = []
        for idx, line in enumerate(content_str.splitlines(), start=1):
            line_str = line.strip()
            if not line_str:
                continue
            try:
                item = json.loads(line_str)
                records.append((idx, item))
            except Exception as e:
                invalids.append(
                    InvalidEventRecord(
                        source_file=file_name,
                        row_number=idx,
                        raw_record=line_str[:500],
                        validation_error=str(e),
                        reason="Malformed JSON line syntax"
                    )
                )
        return records, invalids
