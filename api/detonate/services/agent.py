import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from detonate.api.deps import get_storage
from detonate.models.ai_task import AITask
from detonate.models.submission import Submission
from detonate.prompts.agent import AGENT_SYSTEM
from detonate.services.llm import BaseLLMProvider, LLMMessage

MAX_ITERATIONS = 10


@dataclass
class ToolDefinition:
    name: str
    description: str
    input_schema: dict[str, Any]
    handler: Any  # callable


def _build_tool_schema(tool: ToolDefinition) -> dict[str, Any]:
    return {
        "name": tool.name,
        "description": tool.description,
        "input_schema": tool.input_schema,
    }


# --- Tool handlers ---

def tool_get_file_metadata(submission: Submission, **kwargs: Any) -> str:
    return json.dumps({
        "filename": submission.filename,
        "sha256": submission.file_hash_sha256,
        "md5": submission.file_hash_md5,
        "sha1": submission.file_hash_sha1,
        "file_size": submission.file_size,
        "file_type": submission.file_type,
        "mime_type": submission.mime_type,
        "tags": submission.tags or [],
    })


def tool_extract_strings(submission: Submission, **kwargs: Any) -> str:
    min_length = kwargs.get("min_length", 4)
    max_strings = kwargs.get("max_strings", 200)

    storage = get_storage()
    try:
        data = storage.get_file(submission.storage_path)
    except Exception as e:
        return json.dumps({"error": f"Failed to read file: {e}"})

    # ASCII strings
    ascii_pattern = re.compile(rb"[\x20-\x7e]{%d,}" % min_length)
    strings = [s.decode("ascii") for s in ascii_pattern.findall(data)]

    # UTF-16LE strings
    utf16_pattern = re.compile(
        rb"(?:[\x20-\x7e]\x00){%d,}" % min_length
    )
    for match in utf16_pattern.findall(data):
        try:
            strings.append(match.decode("utf-16-le"))
        except (UnicodeDecodeError, ValueError):
            pass

    # Deduplicate and limit
    unique = list(dict.fromkeys(strings))[:max_strings]
    return json.dumps({
        "total_found": len(strings),
        "returned": len(unique),
        "strings": unique,
    })


def tool_parse_pe_header(submission: Submission, **kwargs: Any) -> str:
    try:
        import pefile
    except ImportError:
        return json.dumps({"error": "pefile not installed"})

    storage = get_storage()
    try:
        data = storage.get_file(submission.storage_path)
    except Exception as e:
        return json.dumps({"error": f"Failed to read file: {e}"})

    try:
        pe = pefile.PE(data=data, fast_load=True)
        pe.parse_data_directories()
    except pefile.PEFormatError:
        return json.dumps({"error": "Not a valid PE file"})

    info: dict[str, Any] = {
        "machine": hex(pe.FILE_HEADER.Machine),
        "number_of_sections": pe.FILE_HEADER.NumberOfSections,
        "timestamp": pe.FILE_HEADER.TimeDateStamp,
        "characteristics": hex(pe.FILE_HEADER.Characteristics),
        "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
    }

    # Sections
    info["sections"] = []
    for s in pe.sections:
        info["sections"].append({
            "name": s.Name.rstrip(b"\x00").decode("ascii", errors="replace"),
            "virtual_size": s.Misc_VirtualSize,
            "raw_size": s.SizeOfRawData,
            "entropy": round(s.get_entropy(), 2),
        })

    # Imports
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        info["imports"] = {}
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode("ascii", errors="replace")
            funcs = []
            for imp in entry.imports:
                if imp.name:
                    funcs.append(imp.name.decode("ascii", errors="replace"))
            info["imports"][dll] = funcs

    pe.close()
    return json.dumps(info)


def tool_analyze_network_iocs(submission: Submission, **kwargs: Any) -> str:
    storage = get_storage()
    try:
        data = storage.get_file(submission.storage_path)
    except Exception as e:
        return json.dumps({"error": f"Failed to read file: {e}"})

    text = data.decode("ascii", errors="ignore")

    # IPs
    ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    ips = list(set(ip_pattern.findall(text)))
    # Filter private/reserved
    ips = [ip for ip in ips if not ip.startswith(("0.", "127.", "255."))]

    # Domains
    domain_pattern = re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
    )
    domains = list(set(domain_pattern.findall(text)))
    # Filter common noise
    noise = {"example.com", "microsoft.com", "google.com", "w3.org", "xml.org"}
    domains = [d for d in domains if d.lower() not in noise][:50]

    # URLs
    url_pattern = re.compile(r"https?://[^\s\"'<>]+")
    urls = list(set(url_pattern.findall(text)))[:50]

    return json.dumps({
        "ips": ips[:50],
        "domains": domains,
        "urls": urls,
    })


def tool_render_verdict(**kwargs: Any) -> str:
    return json.dumps({
        "verdict": kwargs.get("verdict", "unknown"),
        "score": kwargs.get("score", 0),
        "reasoning": kwargs.get("reasoning", ""),
    })


# --- Tool registry ---

def build_tools(submission: Submission) -> list[ToolDefinition]:
    return [
        ToolDefinition(
            name="get_file_metadata",
            description="Get basic metadata about the submitted file (hashes, type, size, etc.)",
            input_schema={"type": "object", "properties": {}, "required": []},
            handler=lambda **kw: tool_get_file_metadata(submission, **kw),
        ),
        ToolDefinition(
            name="extract_strings",
            description="Extract ASCII and UTF-16 strings from the file binary",
            input_schema={
                "type": "object",
                "properties": {
                    "min_length": {
                        "type": "integer",
                        "description": "Minimum string length (default 4)",
                    },
                    "max_strings": {
                        "type": "integer",
                        "description": "Max strings to return (default 200)",
                    },
                },
                "required": [],
            },
            handler=lambda **kw: tool_extract_strings(submission, **kw),
        ),
        ToolDefinition(
            name="parse_pe_header",
            description="Parse PE (Portable Executable) headers. Only works for PE/EXE/DLL files.",
            input_schema={"type": "object", "properties": {}, "required": []},
            handler=lambda **kw: tool_parse_pe_header(submission, **kw),
        ),
        ToolDefinition(
            name="analyze_network_iocs",
            description="Extract network indicators (IPs, domains, URLs) from file strings",
            input_schema={"type": "object", "properties": {}, "required": []},
            handler=lambda **kw: tool_analyze_network_iocs(submission, **kw),
        ),
        ToolDefinition(
            name="render_verdict",
            description="Submit your final verdict. Call this ONLY when analysis is complete.",
            input_schema={
                "type": "object",
                "properties": {
                    "verdict": {
                        "type": "string",
                        "enum": ["clean", "suspicious", "malicious", "unknown"],
                        "description": "Final verdict",
                    },
                    "score": {
                        "type": "integer",
                        "description": "Threat score 0-100",
                    },
                    "reasoning": {
                        "type": "string",
                        "description": "Brief explanation",
                    },
                },
                "required": ["verdict", "score", "reasoning"],
            },
            handler=lambda **kw: tool_render_verdict(**kw),
        ),
    ]


def _gather_evidence(submission: Submission) -> dict[str, str]:
    """Pre-run all tools and collect results (no LLM needed)."""
    tools = build_tools(submission)
    results: dict[str, str] = {}
    for tool in tools:
        if tool.name == "render_verdict":
            continue
        try:
            results[tool.name] = tool.handler()
        except Exception as e:
            results[tool.name] = json.dumps({"error": str(e)})
    return results


_EVIDENCE_PROMPT = (
    "You are analyzing a submitted file. Below is evidence gathered by automated tools. "
    "Based on this evidence, provide your analysis and a final verdict.\n\n"
    "Respond with ONLY a JSON object containing:\n"
    '- "verdict": one of "clean", "suspicious", "malicious", "unknown"\n'
    '- "score": integer 0-100 (0=certainly clean, 100=certainly malicious)\n'
    '- "reasoning": brief explanation of your verdict\n\n'
    "Evidence:\n"
)


async def run_agent_analysis(
    db: AsyncSession,
    llm: BaseLLMProvider,
    submission: Submission,
) -> AITask:
    task = AITask(
        submission_id=submission.id,
        task_type="agent",
        status="running",
        started_at=datetime.now(timezone.utc),
    )
    db.add(task)
    await db.flush()

    try:
        # Gather all evidence upfront (fast, no LLM calls)
        evidence = _gather_evidence(submission)
        tool_calls_log = [
            {"iteration": 1, "tool": name, "result_preview": result[:500]}
            for name, result in evidence.items()
        ]

        # Build a single prompt with all evidence
        evidence_text = "\n\n".join(
            f"### {name}\n```json\n{result}\n```"
            for name, result in evidence.items()
        )
        prompt = _EVIDENCE_PROMPT + evidence_text
        prompt += "\n\nRespond with ONLY the JSON object, no markdown fences."

        resp = await llm.complete(
            messages=[LLMMessage(role="user", content=prompt)],
            system=AGENT_SYSTEM,
        )

        # Parse verdict from response
        content = resp.content.strip()
        if content.startswith("```"):
            content = content.split("\n", 1)[1].rsplit("```", 1)[0].strip()

        try:
            verdict_data = json.loads(content)
        except json.JSONDecodeError:
            verdict_data = {"verdict": "unknown", "score": 0, "reasoning": content}

        task.status = "completed"
        task.output_data = {
            "verdict": verdict_data,
            "tool_calls": tool_calls_log,
            "iterations": 1,
        }
        task.model_used = resp.model
        task.tokens_used = resp.usage
        task.completed_at = datetime.now(timezone.utc)

        # Cache on submission
        v = verdict_data.get("verdict", "unknown")
        if v in ("clean", "suspicious", "malicious", "unknown"):
            submission.ai_verdict = v
        s = verdict_data.get("score")
        if isinstance(s, int) and 0 <= s <= 100:
            submission.ai_score = s
        submission.ai_analyzed_at = datetime.now(timezone.utc)

    except Exception as e:
        task.status = "failed"
        task.error = str(e)
        task.completed_at = datetime.now(timezone.utc)

    await db.flush()
    await db.refresh(task)
    return task
