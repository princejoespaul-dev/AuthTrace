"""CLI for explaining sanitized AuthTrace reports with rules and optional AI."""
import argparse
import json
from pathlib import Path
from .explainer import explain_report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", default="reports/latest.json", help="Path to sanitized AuthTrace report JSON")
    parser.add_argument("--output", default="reports/explained_latest.json", help="Path for annotated report JSON")
    provider = parser.add_mutually_exclusive_group()
    provider.add_argument("--use-openai", action="store_true", help="Use OpenAI API (requires OPENAI_API_KEY)")
    provider.add_argument("--use-ollama", action="store_true", help="Use local Ollama")
    parser.add_argument("--source", action="append", default=[], metavar="PATH", help="Relevant demo API source file or directory; repeatable")
    args = parser.parse_args()
    try:
        report = json.loads(Path(args.input).read_text(encoding="utf-8"))
        explained = explain_report(report, use_ollama=args.use_ollama, use_openai=args.use_openai, source_paths=args.source)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        parser.error(str(exc))
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(explained, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Explained {len(explained['checks'])} checks.")
    print(f"Original overall result preserved: {explained.get('overall')}")
    if args.source and not (args.use_openai or args.use_ollama):
        print("Source paths supplied; pass --use-openai to run code-aware analysis.")
    print(f"Wrote {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
