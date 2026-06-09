"""Challenge (CTF) service: flag hashing/verification, seeding, scoring.

The platform doubles as an auto-graded training ground for the Detonate
Masterclass. Each seeded challenge corresponds to a lab a learner actually does;
the "flag" is a value they recover (a password, an unpacked string, a C2 host,
a campaign id). Flags are stored only as SHA-256 hashes.
"""

from __future__ import annotations

import hashlib

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from detonate.models.challenge import Challenge, ChallengeSolve


def normalize_flag(flag: str) -> str:
    """Normalize a submitted flag before hashing/compare: strip surrounding
    whitespace. (Case and inner content are significant.)"""
    return flag.strip()


def hash_flag(flag: str) -> str:
    return hashlib.sha256(normalize_flag(flag).encode("utf-8")).hexdigest()


def verify_flag(challenge: Challenge, submitted: str) -> bool:
    return hash_flag(submitted) == challenge.flag_hash


# ---------------------------------------------------------------------------
# Seed challenges — each maps to a Masterclass lab. The flag is the value the
# learner recovers by doing that lab. (All values are from benign training
# binaries; no secrets here.)
# ---------------------------------------------------------------------------

SEED_CHALLENGES: list[dict] = [
    {
        "slug": "crackme-flag",
        "title": "Read a Debugger",
        "description": (
            "Build and analyze the crackme from Masterclass Module 1.3. Recover "
            "the flag it prints for the correct password. Submit the FLAG{...} value."
        ),
        "category": "foundations",
        "difficulty": "beginner",
        "points": 100,
        "flag": "FLAG{you_can_read_a_debugger}",
        "hints": [
            "The password is built byte-by-byte on the stack (Module 1.3).",
            "Recover it from the immediate `mov BYTE PTR` stores, or break on "
            "check_password in gdb.",
        ],
        "module_ref": "masterclass/01-foundations/03-re-toolchain",
        "order_index": 10,
    },
    {
        "slug": "unpack-the-stub",
        "title": "Dump at the OEP",
        "description": (
            "Module 4.2 ships an encrypted stub. Recover the plaintext payload it "
            "decrypts at runtime — statically (recover the key) or by dumping at the OEP."
        ),
        "category": "unpacking",
        "difficulty": "intermediate",
        "points": 200,
        "flag": "FLAG{unpacked_at_runtime}",
        "hints": [
            "The XOR key is the ASCII string referenced by the decrypt loop.",
            "Or: break on `unpack`, save $rdi, finish, x/s the buffer.",
        ],
        "module_ref": "masterclass/04-unpacking-deobfuscation/02-custom-packers",
        "order_index": 20,
    },
    {
        "slug": "deobfuscate-c2",
        "title": "Defeat the Obfuscation",
        "description": (
            "Module 4.3's sample hides its C2 with single-byte XOR. Recover the "
            "C2 hostname and submit it (e.g. host.tld)."
        ),
        "category": "deobfuscation",
        "difficulty": "intermediate",
        "points": 150,
        "flag": "c2.example.com",
        "hints": [
            "It's a single-byte XOR. Brute-force all 256 keys and look for a domain.",
            "deobf.py (Module 4.4) automates this — key 0x5a.",
        ],
        "module_ref": "masterclass/04-unpacking-deobfuscation/03-string-api-obfuscation",
        "order_index": 30,
    },
    {
        "slug": "extract-the-config",
        "title": "Pull the Campaign ID",
        "description": (
            "Module 6.1's configbot carries an RC4-encrypted config behind a CFG0 "
            "marker. Decrypt it and submit the campaign id."
        ),
        "category": "config-extraction",
        "difficulty": "advanced",
        "points": 250,
        "flag": "TRAIN-2026",
        "hints": [
            "Find the CFG0 marker; the layout is CFG0 | uint16 len | RC4(config).",
            "RC4 key is the string referenced by the key-schedule "
            "(Module 6.2's extractor does it).",
        ],
        "module_ref": "masterclass/06-config-extraction/01-decrypting-config",
        "order_index": 40,
    },
    {
        "slug": "capstone-botid",
        "title": "Capstone: Identify the Bot",
        "description": (
            "Build the Level 7 capstone (challenge/build.sh) and run the full kill "
            "chain on crackmalware: unpack, bypass anti-debug, decrypt the config. "
            "Submit the bot/campaign id."
        ),
        "category": "capstone",
        "difficulty": "advanced",
        "points": 500,
        "flag": "CAPSTONE-01",
        "hints": [
            "It's UPX-packed; `upx -d` first.",
            "ptrace anti-debug — force the return to 0. Then RC4 (key 'unpackme!') the CFG0 blob.",
        ],
        "module_ref": "masterclass/07-capstone",
        "order_index": 50,
    },
]


async def seed_default_challenges(db: AsyncSession) -> int:
    """Insert any missing seed challenges (idempotent by slug). Returns count added."""
    added = 0
    for c in SEED_CHALLENGES:
        exists = await db.execute(select(Challenge.id).where(Challenge.slug == c["slug"]))
        if exists.scalar_one_or_none() is not None:
            continue
        db.add(
            Challenge(
                slug=c["slug"],
                title=c["title"],
                description=c["description"],
                category=c["category"],
                difficulty=c["difficulty"],
                points=c["points"],
                flag_hash=hash_flag(c["flag"]),
                hints=c["hints"],
                module_ref=c["module_ref"],
                order_index=c["order_index"],
            )
        )
        added += 1
    if added:
        await db.flush()
    return added


async def solve_count(db: AsyncSession, challenge_id) -> int:
    result = await db.execute(
        select(func.count()).select_from(ChallengeSolve).where(
            ChallengeSolve.challenge_id == challenge_id
        )
    )
    return int(result.scalar_one() or 0)


async def has_solved(db: AsyncSession, challenge_id, player: str) -> bool:
    result = await db.execute(
        select(ChallengeSolve.id).where(
            ChallengeSolve.challenge_id == challenge_id,
            ChallengeSolve.player == player,
        )
    )
    return result.scalar_one_or_none() is not None
