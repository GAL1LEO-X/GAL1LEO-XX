# Third-party notices

Original bridge code and GAL1LEO contributions are Apache-2.0. Upstream
software, models, assets and dependencies retain their own terms.

The pinned WAHA and GOWS upstream commits have Apache-2.0 LICENSE files.
Copies from the exact pinned sources are retained under provider-checkpoint/
licenses/. The source patches preserve upstream context and attribution.
WAHA package metadata says UNLICENSED at that pin; its LICENSE text does not
by itself clear Plus features, dashboard assets or every packaged component.
The public reconstruction workflow targets the source integration, and the
API-only runtime recipes omit dashboard/Plus assets.

Compiled provider distributions have additional obligations. Recorded examples
include GPL-3.0 libsignal, MPL-2.0 Whatsmeow, LGPL libvips and GPL-enabled FFmpeg.
Determine the terms of the exact linked/packaged aggregate and supply notices,
corresponding source and other required material before redistributing it.
This repository does not distribute those compiled runtime images.

Python packages in requirements*.lock and optional transcription dependencies
retain their own licenses. The pinned Whisper model is identified as MIT in
transcription-model.json; model files are not included or automatically fetched.
WhatsApp/OpenAI names and marks do not imply endorsement or transfer trademark
rights. Check the requirements of your target client and asset use separately.
