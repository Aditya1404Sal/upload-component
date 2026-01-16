# HTTP File Upload Component

This is a Rust-based WebAssembly (WASI 0.2) component that acts as a file handler. It accepts a JSON request via HTTP, downloads a file from a specified source URL, saves it to the local filesystem (temporarily), and is designed to upload it to a target destination (e.g., S3).

## Prerequisites

- `cargo` 1.82+
- [`wash`](https://wasmcloud.com/docs/installation) 0.36.1+
- `wasmtime` >=25.0.0 (required for local testing)

## Building

```bash
wash build
```

*Note: This generates the component binary in the `./build` directory (usually named `file_upload.wasm` or similar based on your `wasm.toml` config).*

## Running with Wasmtime

Because this component interacts with the **filesystem** (to save temporary files) and the **network** (to download files), you must provide explicit permissions via CLI flags.

**1. Create a directory for uploads (optional but recommended):**
To keep your project root clean, create a folder for the component to use: (it already exists in this dir, so just delete the dummy.pdf for now)

```bash
mkdir tmp_uploads
```

**2. Run the component:**
You must map a host directory (e.g., `./tmp_uploads`) to the guest's root (`/`) using the `--dir` flag.

```bash
wasmtime serve --dir ./tmp_uploads::/ -Scommon -Sinherit-env=y ./build/file_upload.wasm
```

* `--dir ./tmp_uploads::/`: Maps your local `tmp_uploads` folder to `/` inside the WASM sandbox.
* `-Scommon`: Grants network and I/O capabilities.
* `-Sinherit-env=y`: Inherits environment variables.

## Testing the Component

Once the component is running (default port 8080), you can trigger the download flow using this `curl` request:

```bash
curl -X POST http://localhost:8080 \
  -H "Content-Type: application/json" \
  -d '{
    "applicationId": "test-app",
    "actionId": "test-action",
    "logId": "test-log",
    "model": {
      "name": "TestModel"
    },
    "property": {
      "name": "testFile"
    },
    "url": "[https://www.w3.org/WAI/ER/tests/xhtml/testfiles/resources/pdf/dummy.pdf](https://www.w3.org/WAI/ER/tests/xhtml/testfiles/resources/pdf/dummy.pdf)"
  }'
```

**Expected Output:**
If successful, the component will download `dummy.pdf`, save it to your `tmp_uploads` directory, and respond with:
`File uploaded successfully! Reference: reference, Size: 13264 bytes`

## Running with wasmCloud

TODO