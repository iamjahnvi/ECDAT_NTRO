"""CI entry point: python cli.py --config targets.json --output cbom.json."""
import argparse
import json
import os
from pathlib import Path
import httpx


def main():
    parser = argparse.ArgumentParser(description='ECDAT enterprise discovery CI client')
    parser.add_argument('--config', required=True, help='DiscoveryRequest JSON file')
    parser.add_argument('--output', default='cbom.json')
    parser.add_argument('--api', default=os.environ.get('ECDAT_API_URL', 'http://localhost:8000'))
    parser.add_argument('--fail-on', choices=['critical', 'high', 'never'], default='critical')
    args = parser.parse_args()
    try:
        config = json.loads(Path(args.config).read_text())
        token = os.environ.get('ECDAT_API_KEY')
        response = httpx.post(args.api.rstrip('/') + '/discover', json=config,
            headers={'Authorization': f'Bearer {token}'} if token else {}, timeout=1800)
        response.raise_for_status()
        bom = response.json()
        Path(args.output).write_text(json.dumps(bom, indent=2))
        props = {p['name']: json.loads(p['value']) for p in bom.get('properties', []) if p['name'].startswith('ecdat:')}
        summary = props.get('ecdat:summary', {})
        print(json.dumps(summary))
        if props.get('ecdat:discovery_errors'):
            print('Discovery incomplete; inspect ecdat:discovery_errors in output.')
            return 2
        if args.fail_on != 'never' and (summary.get('critical_count', 0) or (args.fail_on == 'high' and summary.get('high_count', 0))):
            return 1
        return 0
    except (OSError, ValueError, httpx.HTTPError) as exc:
        print(f'Discovery failed: {exc}')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
