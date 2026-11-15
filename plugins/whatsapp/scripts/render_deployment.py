"""Produce reviewable configuration without installing services or changing accounts."""
import argparse
import json
from pathlib import Path
import re
import shutil

parser=argparse.ArgumentParser()
parser.add_argument("--domain",required=True)
parser.add_argument("--output",type=Path,required=True)
args=parser.parse_args()
if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?",args.domain) or "." not in args.domain:
    parser.error("A DNS hostname is required")
if args.output.exists():
    parser.error("Output already exists; choose a new directory")
root=Path(__file__).resolve().parents[1]
args.output.mkdir(parents=True)
plugin=args.output/"plugin"
plugin.mkdir()
shutil.copyfile(root/"plugin/plugin.json",plugin/"plugin.json")
shutil.copytree(root/"plugin/assets",plugin/"assets")
value=(root/"plugin/mcp.json.in").read_text().replace("__DOMAIN__",args.domain)
json.loads(value)
(plugin/"mcp.json").write_text(value,encoding="utf-8")
(args.output/"apache-whatsapp.conf").write_text((root/"deploy/apache-whatsapp.conf.in").read_text().replace("__DOMAIN__",args.domain),encoding="utf-8")
lock=json.loads((root/"deploy/images.lock.json").read_text())
container=(root/"deploy/whatsapp-waha.container").read_text()
container=re.sub(r"^Image=.*$","Image="+lock["waha_image"],container,flags=re.MULTILINE)
(args.output/"whatsapp-waha.container").write_text(container,encoding="utf-8")
shutil.copyfile(root/"deploy/whatsapp-personal.service",args.output/"whatsapp-personal.service")
print("Prepared configuration only. No deployment, account linking or plugin registration performed.")

