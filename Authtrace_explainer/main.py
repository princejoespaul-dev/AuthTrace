"""CLI for explaining a sanitized AuthTrace reports/latest.json report."""
import argparse
import json
from pathlib import Path

from .explainer import explain_report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", default="reports/latest.json", help="Path to sanitized AuthTrace report JSON")
    parser.add_argument("--output", default="reports/explained_latest.json", help="Path for annotated report JSON")
    parser.add_argument("--use-ollama", action="store_true", help="Use local Ollama for wording; rules remain the fallback")
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)
    try:
        report = json.loads(input_path.read_text(encoding="utf-8"))
        explained = explain_report(report, use_ollama=args.use_ollama)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        parser.error(str(exc))

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(explained, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Explained {len(explained['checks'])} checks.")
    print(f"Original overall result preserved: {explained.get('overall')}")
    print(f"Wrote {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
