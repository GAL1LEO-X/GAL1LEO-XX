# Third-party notices

GAL1LEO's original code is Apache-2.0. This does not replace upstream licenses.

- The Tesla vehicle-command adapter and its source patch are Apache-2.0.
  Exact pins are in deploy/components.lock.json and proxy-extension/provenance.json.
  Retain deploy/proxy-extension/LICENSE.txt, NOTICE.txt and TESLEMETRY-NOTICE.txt.
- Adapted protobuf definitions originate from Tesla and Teslemetry, with
  additional Google protocol provenance recorded in those notices.
- Fleet Telemetry, Kafka, Go build/runtime images and all Python packages
  retain their own terms. The dependency locks identify the selected versions.
  Runtime containers are external inputs, not redistributed in this repository.
- Product names, logos and illustrations do not grant trademark rights or
  imply an official Tesla/OpenAI product. Review asset rights for your own listing.

Distribution of a compiled aggregate requires an inventory of the exact
included components and their notices. Do not infer redistribution rights
solely from the license of this wrapper.
