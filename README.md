# appstore-upload-utils

ZIP/PDF/image content checks shared by the AppStore backend, Online-IDE and Web-LaTeX.

Install: `pip install git+https://github.com/DHBW-AppStore-T3/appstore-upload-utils.git@v1.0.0`

## Modules

- `appstore_upload_utils.upload_validation` – `inspect_upload(name, data, allowed_exts)` → `InspectedUpload`
- `appstore_upload_utils.upload_formats` – PDF and image structure checks used by the validator
