from __future__ import annotations

import hashlib
import io
import json
import logging
import re
import zipfile
from datetime import datetime, timedelta, timezone
from typing import Any
from xml.etree import ElementTree

import psycopg2
import psycopg2.extras
import requests

from helpers import get_connection

logger = logging.getLogger(__name__)

try:
    from pypdf import PdfReader
except Exception:  # pragma: no cover - optional dependency
    PdfReader = None

try:
    from docx import Document as DocxDocument
except Exception:  # pragma: no cover - optional dependency
    DocxDocument = None

CHUNK_SIZE = 1400
CHUNK_OVERLAP = 200
REQUEST_TIMEOUT_SECONDS = 20

FREE_RESEARCH_SOURCES = (
    {
        "source_key": "pubmed_exercise_reviews",
        "source_type": "pubmed_query",
        "source_label": "PubMed systematic reviews",
        "evidence_tier": 1,
        "query": '((exercise[Title/Abstract] OR "physical activity"[Title/Abstract] OR "resistance training"[Title/Abstract] OR nutrition[Title/Abstract] OR wellbeing[Title/Abstract] OR "behavior change"[Title/Abstract]) AND (systematic review[Publication Type] OR meta-analysis[Publication Type]))',
        "retmax": 8,
    },
    {
        "source_key": "pubmed_behavior_change_reviews",
        "source_type": "pubmed_query",
        "source_label": "PubMed behavior-change reviews",
        "evidence_tier": 1,
        "query": '(("behavior change"[Title/Abstract] OR coaching[Title/Abstract] OR wellbeing[Title/Abstract] OR "lifestyle medicine"[Title/Abstract] OR motivation[Title/Abstract]) AND (systematic review[Publication Type] OR meta-analysis[Publication Type]))',
        "retmax": 8,
    },
    {
        "source_key": "who_news",
        "source_type": "rss",
        "source_label": "WHO News",
        "evidence_tier": 1,
        "feed_url": "https://www.who.int/rss-feeds/news-english.xml",
    },
    {
        "source_key": "cdc_physical_activity_basics",
        "source_type": "html_page",
        "source_label": "CDC Physical Activity Basics",
        "evidence_tier": 1,
        "page_url": "https://www.cdc.gov/physicalactivity/basics/index.htm",
        "title": "CDC Physical Activity Basics and Your Health",
    },
    {
        "source_key": "cdc_adult_activity_benefits",
        "source_type": "html_page",
        "source_label": "CDC Adult Activity Benefits",
        "evidence_tier": 1,
        "page_url": "https://www.cdc.gov/physical-activity-basics/health-benefits/adults.html",
        "title": "CDC Health Benefits of Physical Activity for Adults",
    },
    {
        "source_key": "ace_fitfacts_index",
        "source_type": "html_page",
        "source_label": "ACE Fit Facts",
        "evidence_tier": 2,
        "page_url": "https://www.acefitness.org/resources/everyone/blog/fit-facts/",
        "title": "ACE Fit Facts",
    },
    {
        "source_key": "ace_rss_directory",
        "source_type": "html_page",
        "source_label": "ACE RSS Feeds",
        "evidence_tier": 2,
        "page_url": "https://www.acefitness.org/about-ace/rss/",
        "title": "ACE RSS Feeds",
    },
)


def _clean_text(value: str | None) -> str:
    if not value:
        return ""
    text = re.sub(r"<[^>]+>", " ", value)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def _clean_filename(name: str | None) -> str:
    if not name:
        return "Untitled Document"
    cleaned = re.sub(r"[^A-Za-z0-9._ -]+", " ", name).strip()
    return cleaned or "Untitled Document"


def _chunk_text(text: str, *, chunk_size: int = CHUNK_SIZE, overlap: int = CHUNK_OVERLAP) -> list[str]:
    normalized = _clean_text(text)
    if not normalized:
        return []
    chunks: list[str] = []
    cursor = 0
    length = len(normalized)
    while cursor < length:
        end = min(length, cursor + chunk_size)
        if end < length:
            boundary = normalized.rfind(" ", cursor, end)
            if boundary > cursor + int(chunk_size * 0.6):
                end = boundary
        chunk = normalized[cursor:end].strip()
        if chunk:
            chunks.append(chunk)
        if end >= length:
            break
        cursor = max(end - overlap, cursor + 1)
    return chunks


def _read_docx_bytes(raw_bytes: bytes) -> str:
    if DocxDocument is not None:
        document = DocxDocument(io.BytesIO(raw_bytes))
        return "\n".join(paragraph.text for paragraph in document.paragraphs if paragraph.text).strip()

    with zipfile.ZipFile(io.BytesIO(raw_bytes)) as archive:
        with archive.open("word/document.xml") as handle:
            xml_content = handle.read()
    xml_root = ElementTree.fromstring(xml_content)
    namespaces = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}
    segments = [node.text for node in xml_root.findall(".//w:t", namespaces) if node.text]
    return "\n".join(segments).strip()


def _read_pdf_bytes(raw_bytes: bytes) -> str:
    if PdfReader is None:
        raise ValueError("PDF uploads require the pypdf package in the runtime environment.")
    reader = PdfReader(io.BytesIO(raw_bytes))
    pages: list[str] = []
    for page in reader.pages:
        pages.append(page.extract_text() or "")
    return "\n".join(part for part in pages if part).strip()


def extract_uploaded_text(file_storage) -> tuple[str, str]:
    filename = _clean_filename(getattr(file_storage, "filename", None))
    raw_bytes = file_storage.read()
    if not raw_bytes:
        raise ValueError("The uploaded file is empty.")
    lower_name = filename.lower()
    if lower_name.endswith((".txt", ".md", ".markdown")):
        text = raw_bytes.decode("utf-8", errors="ignore")
    elif lower_name.endswith(".docx"):
        text = _read_docx_bytes(raw_bytes)
    elif lower_name.endswith(".pdf"):
        text = _read_pdf_bytes(raw_bytes)
    else:
        raise ValueError("Unsupported upload type. Use .txt, .md, .docx, or .pdf.")
    text = _clean_text(text)
    if not text:
        raise ValueError("No readable text was found in that file.")
    return filename, text


def ingest_document(
    *,
    created_by: int | None,
    document_kind: str,
    title: str,
    content_text: str,
    source_type: str = "manual",
    source_key: str | None = None,
    source_url: str | None = None,
    source_label: str | None = None,
    published_at: datetime | None = None,
    evidence_tier: int = 2,
    metadata: dict[str, Any] | None = None,
    approval_status: str = "approved",
) -> dict[str, Any]:
    cleaned_title = _clean_text(title) or "Untitled Document"
    cleaned_content = _clean_text(content_text)
    if not cleaned_content:
        raise ValueError("Document content is empty.")

    metadata = metadata or {}
    content_hash = hashlib.sha256(cleaned_content.encode("utf-8")).hexdigest()
    if not source_key:
        source_key = hashlib.sha256(f"{document_kind}:{cleaned_title}:{source_url or ''}".encode("utf-8")).hexdigest()
    chunks = _chunk_text(cleaned_content)
    if not chunks:
        raise ValueError("Document content could not be chunked.")

    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(
                """
                INSERT INTO agent_documents (
                    document_kind,
                    source_type,
                    source_key,
                    title,
                    content_text,
                    summary_text,
                    source_url,
                    source_label,
                    published_at,
                    evidence_tier,
                    approval_status,
                    metadata,
                    content_hash,
                    created_by
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (source_key)
                DO UPDATE SET
                    title = EXCLUDED.title,
                    content_text = EXCLUDED.content_text,
                    summary_text = EXCLUDED.summary_text,
                    source_url = EXCLUDED.source_url,
                    source_label = EXCLUDED.source_label,
                    published_at = EXCLUDED.published_at,
                    evidence_tier = EXCLUDED.evidence_tier,
                    approval_status = EXCLUDED.approval_status,
                    metadata = EXCLUDED.metadata,
                    content_hash = EXCLUDED.content_hash,
                    updated_at = CURRENT_TIMESTAMP
                RETURNING id, source_key, content_hash
                """,
                (
                    document_kind,
                    source_type,
                    source_key,
                    cleaned_title,
                    cleaned_content,
                    chunks[0][:500],
                    source_url,
                    source_label,
                    published_at,
                    evidence_tier,
                    approval_status,
                    psycopg2.extras.Json(metadata),
                    content_hash,
                    created_by,
                ),
            )
            document_row = cursor.fetchone()
            document_id = document_row["id"]
            cursor.execute("DELETE FROM agent_document_chunks WHERE document_id = %s", (document_id,))
            psycopg2.extras.execute_batch(
                cursor,
                """
                INSERT INTO agent_document_chunks (document_id, chunk_index, chunk_text, metadata)
                VALUES (%s, %s, %s, %s)
                """,
                [
                    (
                        document_id,
                        index,
                        chunk,
                        psycopg2.extras.Json(
                            {
                                "document_kind": document_kind,
                                "evidence_tier": evidence_tier,
                                "source_label": source_label,
                            }
                        ),
                    )
                    for index, chunk in enumerate(chunks)
                ],
            )
            conn.commit()

    return {
        "document_id": document_id,
        "source_key": source_key,
        "title": cleaned_title,
        "chunk_count": len(chunks),
        "content_hash": content_hash,
    }


def search_retrieval_context(
    query: str,
    *,
    manuscript_limit: int = 2,
    research_limit: int = 3,
) -> dict[str, list[dict[str, Any]]]:
    search_text = _clean_text(query)
    if not search_text:
        return {"manuscript": [], "research": [], "citations": []}

    results: dict[str, list[dict[str, Any]]] = {"manuscript": [], "research": [], "citations": []}
    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            for document_kind, limit in (("manuscript", manuscript_limit), ("research", research_limit)):
                cursor.execute(
                    """
                    SELECT d.id AS document_id,
                           d.title,
                           d.source_url,
                           d.source_label,
                           d.published_at,
                           d.evidence_tier,
                           c.chunk_text,
                           ts_rank_cd(
                               to_tsvector('english', COALESCE(d.title, '') || ' ' || COALESCE(c.chunk_text, '')),
                               plainto_tsquery('english', %s)
                           ) AS rank_value
                      FROM agent_document_chunks c
                      JOIN agent_documents d
                        ON d.id = c.document_id
                     WHERE d.document_kind = %s
                       AND d.approval_status = 'approved'
                       AND to_tsvector('english', COALESCE(d.title, '') || ' ' || COALESCE(c.chunk_text, ''))
                           @@ plainto_tsquery('english', %s)
                     ORDER BY rank_value DESC,
                              COALESCE(d.published_at, d.updated_at, d.created_at) DESC
                     LIMIT %s
                    """,
                    (search_text, document_kind, search_text, limit),
                )
                rows = cursor.fetchall() or []
                if not rows:
                    cursor.execute(
                        """
                        SELECT d.id AS document_id,
                               d.title,
                               d.source_url,
                               d.source_label,
                               d.published_at,
                               d.evidence_tier,
                               c.chunk_text
                          FROM agent_document_chunks c
                          JOIN agent_documents d
                            ON d.id = c.document_id
                         WHERE d.document_kind = %s
                           AND d.approval_status = 'approved'
                           AND (
                                LOWER(d.title) LIKE LOWER(%s)
                                OR LOWER(c.chunk_text) LIKE LOWER(%s)
                           )
                         ORDER BY COALESCE(d.published_at, d.updated_at, d.created_at) DESC
                         LIMIT %s
                        """,
                        (document_kind, f"%{search_text}%", f"%{search_text}%", limit),
                    )
                    rows = cursor.fetchall() or []

                key = "manuscript" if document_kind == "manuscript" else "research"
                for row in rows:
                    published_at = row.get("published_at")
                    published_label = None
                    if isinstance(published_at, datetime):
                        if published_at.tzinfo is None:
                            published_at = published_at.replace(tzinfo=timezone.utc)
                        published_label = published_at.date().isoformat()
                    item = {
                        "document_id": row.get("document_id"),
                        "title": row.get("title"),
                        "source_url": row.get("source_url"),
                        "source_label": row.get("source_label"),
                        "published_at": published_at.isoformat() if isinstance(published_at, datetime) else None,
                        "published_label": published_label,
                        "evidence_tier": row.get("evidence_tier"),
                        "content": row.get("chunk_text"),
                    }
                    results[key].append(item)
                    citation = {
                        "title": row.get("title"),
                        "url": row.get("source_url"),
                        "label": row.get("source_label") or row.get("title"),
                        "published_at": published_label,
                        "evidence_tier": row.get("evidence_tier"),
                    }
                    if citation not in results["citations"]:
                        results["citations"].append(citation)
    return results


def _fetch_pubmed_documents(source: dict[str, Any]) -> list[dict[str, Any]]:
    search_url = "https://eutils.ncbi.nlm.nih.gov/entrez/eutils/esearch.fcgi"
    summary_url = "https://eutils.ncbi.nlm.nih.gov/entrez/eutils/esummary.fcgi"
    fetch_url = "https://eutils.ncbi.nlm.nih.gov/entrez/eutils/efetch.fcgi"
    cutoff = datetime.now(timezone.utc) - timedelta(days=120)

    search_response = requests.get(
        search_url,
        params={
            "db": "pubmed",
            "retmode": "json",
            "sort": "pub_date",
            "retmax": source.get("retmax", 8),
            "term": source["query"],
        },
        timeout=REQUEST_TIMEOUT_SECONDS,
    )
    search_response.raise_for_status()
    id_list = search_response.json().get("esearchresult", {}).get("idlist", [])
    if not id_list:
        return []

    summary_response = requests.get(
        summary_url,
        params={"db": "pubmed", "retmode": "json", "id": ",".join(id_list)},
        timeout=REQUEST_TIMEOUT_SECONDS,
    )
    summary_response.raise_for_status()
    summary_payload = summary_response.json().get("result", {})

    fetch_response = requests.get(
        fetch_url,
        params={"db": "pubmed", "retmode": "xml", "id": ",".join(id_list)},
        timeout=REQUEST_TIMEOUT_SECONDS,
    )
    fetch_response.raise_for_status()
    xml_root = ElementTree.fromstring(fetch_response.content)

    abstract_map: dict[str, str] = {}
    for article in xml_root.findall(".//PubmedArticle"):
        pmid_node = article.find(".//PMID")
        if pmid_node is None or not pmid_node.text:
            continue
        abstract_parts = []
        for abstract_node in article.findall(".//Abstract/AbstractText"):
            label = abstract_node.attrib.get("Label")
            value = "".join(abstract_node.itertext()).strip()
            if not value:
                continue
            abstract_parts.append(f"{label}: {value}" if label else value)
        abstract_map[pmid_node.text.strip()] = _clean_text(" ".join(abstract_parts))

    documents: list[dict[str, Any]] = []
    for pubmed_id in id_list:
        entry = summary_payload.get(pubmed_id) or {}
        title = _clean_text(entry.get("title"))
        if not title:
            continue
        pubdate = _clean_text(entry.get("pubdate"))
        published_at = None
        for candidate in ("%Y %b %d", "%Y %b", "%Y"):
            try:
                published_at = datetime.strptime(pubdate, candidate).replace(tzinfo=timezone.utc)
                break
            except ValueError:
                continue
        if published_at and published_at < cutoff:
            continue
        body = abstract_map.get(pubmed_id) or title
        documents.append(
            {
                "source_key": f"{source['source_key']}:{pubmed_id}",
                "title": title,
                "content_text": body,
                "source_url": f"https://pubmed.ncbi.nlm.nih.gov/{pubmed_id}/",
                "source_label": source["source_label"],
                "published_at": published_at,
                "evidence_tier": source["evidence_tier"],
                "source_type": source["source_type"],
                "metadata": {"pubmed_id": pubmed_id, "query": source["query"]},
            }
        )
    return documents


def _parse_rss_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    value = value.strip()
    formats = (
        "%a, %d %b %Y %H:%M:%S %z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%d",
    )
    for fmt in formats:
        try:
            parsed = datetime.strptime(value, fmt)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except ValueError:
            continue
    return None


def _fetch_rss_documents(source: dict[str, Any]) -> list[dict[str, Any]]:
    response = requests.get(source["feed_url"], timeout=REQUEST_TIMEOUT_SECONDS)
    response.raise_for_status()
    xml_root = ElementTree.fromstring(response.content)
    documents: list[dict[str, Any]] = []
    items = xml_root.findall(".//item")
    if not items:
        items = xml_root.findall(".//{http://www.w3.org/2005/Atom}entry")
    cutoff = datetime.now(timezone.utc) - timedelta(days=120)
    for index, item in enumerate(items[:10], start=1):
        title = _clean_text(item.findtext("title") or item.findtext("{http://www.w3.org/2005/Atom}title"))
        link = item.findtext("link")
        if not link:
            link_node = item.find("link")
            if link_node is not None:
                link = link_node.attrib.get("href") or link_node.text
        description = _clean_text(
            item.findtext("description")
            or item.findtext("summary")
            or item.findtext("{http://www.w3.org/2005/Atom}summary")
        )
        published_raw = (
            item.findtext("pubDate")
            or item.findtext("published")
            or item.findtext("{http://www.w3.org/2005/Atom}published")
            or item.findtext("{http://www.w3.org/2005/Atom}updated")
        )
        published_at = _parse_rss_timestamp(published_raw)
        if published_at and published_at < cutoff:
            continue
        if not title:
            continue
        documents.append(
            {
                "source_key": f"{source['source_key']}:{hashlib.sha256((link or title).encode('utf-8')).hexdigest()}",
                "title": title,
                "content_text": description or title,
                "source_url": link,
                "source_label": source["source_label"],
                "published_at": published_at,
                "evidence_tier": source["evidence_tier"],
                "source_type": source["source_type"],
                "metadata": {"feed_url": source["feed_url"], "item_index": index},
            }
        )
    return documents


def _fetch_html_page_documents(source: dict[str, Any]) -> list[dict[str, Any]]:
    response = requests.get(source["page_url"], timeout=REQUEST_TIMEOUT_SECONDS)
    response.raise_for_status()
    html = response.text
    title_match = re.search(r"<title>(.*?)</title>", html, flags=re.IGNORECASE | re.DOTALL)
    title = _clean_text(title_match.group(1) if title_match else source.get("title") or source.get("source_label"))
    body_match = re.search(r"<body[^>]*>(.*)</body>", html, flags=re.IGNORECASE | re.DOTALL)
    body_text = _clean_text(body_match.group(1) if body_match else html)
    if len(body_text) > 8000:
        body_text = body_text[:8000]
    return [
        {
            "source_key": source["source_key"],
            "title": title or source.get("title") or source.get("source_label") or source["source_key"],
            "content_text": body_text,
            "source_url": source["page_url"],
            "source_label": source["source_label"],
            "published_at": None,
            "evidence_tier": source["evidence_tier"],
            "source_type": source["source_type"],
            "metadata": {"page_url": source["page_url"]},
        }
    ]


def sync_free_research_sources(*, triggered_by_user_id: int | None = None) -> dict[str, Any]:
    run_id = None
    inserted = 0
    updated_sources: list[dict[str, Any]] = []
    errors: list[str] = []

    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(
                """
                INSERT INTO agent_research_sync_runs (triggered_by, status, metadata)
                VALUES (%s, %s, %s)
                RETURNING id
                """,
                (triggered_by_user_id, "running", psycopg2.extras.Json({"source_count": len(FREE_RESEARCH_SOURCES)})),
            )
            run_id = cursor.fetchone()["id"]
            conn.commit()

    try:
        for source in FREE_RESEARCH_SOURCES:
            try:
                if source["source_type"] == "pubmed_query":
                    documents = _fetch_pubmed_documents(source)
                elif source["source_type"] == "rss":
                    documents = _fetch_rss_documents(source)
                elif source["source_type"] == "html_page":
                    documents = _fetch_html_page_documents(source)
                else:
                    documents = []
                for document in documents:
                    ingest_document(
                        created_by=triggered_by_user_id,
                        document_kind="research",
                        title=document["title"],
                        content_text=document["content_text"],
                        source_type=document["source_type"],
                        source_key=document["source_key"],
                        source_url=document.get("source_url"),
                        source_label=document.get("source_label"),
                        published_at=document.get("published_at"),
                        evidence_tier=document.get("evidence_tier", source.get("evidence_tier", 2)),
                        metadata=document.get("metadata") or {},
                        approval_status="approved",
                    )
                    inserted += 1
                updated_sources.append({"source_key": source["source_key"], "count": len(documents)})
            except Exception as exc:  # pragma: no cover - network/runtime dependent
                logger.exception("Agent research sync failed for %s", source["source_key"])
                errors.append(f"{source['source_key']}: {exc}")
    finally:
        with get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE agent_research_sync_runs
                       SET status = %s,
                           completed_at = CURRENT_TIMESTAMP,
                           metadata = %s
                     WHERE id = %s
                    """,
                    (
                        "completed" if not errors else "completed_with_errors",
                        psycopg2.extras.Json({"inserted": inserted, "sources": updated_sources, "errors": errors}),
                        run_id,
                    ),
                )
                conn.commit()

    return {"run_id": run_id, "inserted": inserted, "sources": updated_sources, "errors": errors}
