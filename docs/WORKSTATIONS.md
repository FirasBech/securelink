# SecureLink workstation: first version

The workstation feature lets a controller use a Windows or Unix computer over
an existing OpenSSH connection. A separately started worker runs explicitly
enabled Codex, Claude Code, OpenCode, Blender or ComfyUI jobs. Both computers need a
copy of SecureLink. This is a first version: validate on your actual machines
before depending on it, especially for unattended or GPU-heavy work.

## Prepare the workstation

1. Install Python and the agent tools or Blender you intend to use. Sign in to
   each agent on the workstation using that provider's normal setup.
2. Copy this repository to the workstation. To make a source-only bundle on the
   controller, run `python scripts/package_workstation.py`; transfer and unpack
   the resulting zip. The bundle does not include Python, dependencies, agent
   credentials, private configuration or test files. To install the included
   application's dependencies on the workstation, run `python -m pip install
   -r requirements-runtime.txt` from its extracted SecureLink folder.
3. Install Tailscale and sign both computers into the same tailnet, or share the
   workstation device with the controller through Tailscale. The desktop
   Workstation tab can list Tailscale devices and fill the SSH target. Then
   install and configure OpenSSH Server on the Windows workstation. Set up an SSH key
   for the controller, and verify the workstation host key by a trusted method.
   Confirm that `ssh user@workstation` works with key authentication. SecureLink
   uses `BatchMode=yes` and `StrictHostKeyChecking=yes`: it will not accept a new
   host key or prompt for passwords. Use LAN or a private VPN.

   Windows uses **OpenSSH over Tailscale** here; Tailscale's own SSH server does
   not run on Windows. SecureLink optionally uses the dedicated private key
   `~/.ssh/securelink_workstation_ed25519` if present, alongside ordinary SSH
   identities. Install only its `.pub` public key into the remote account's
   OpenSSH authorized keys; never copy its private key. Verify the remote SSH
   host fingerprint with the workstation owner before accepting it.
4. In the workstation's SecureLink project directory, choose an existing
   workspace for jobs and files:

   ```powershell
   python -m ui.remote_worker configure --workspace "D:\SecureLinkProjects"
   ```

5. Start a worker and explicitly enable the tools it can run:

   ```powershell
   python -m ui.remote_worker serve --enable codex --enable blender --slots 2
   ```

   Supported names are `codex`, `claude`, `opencode`, and `blender`. `--slots`
   controls simultaneous jobs, not the number of GPUs. Add `--claude-path`,
   `--codex-path`, `--opencode-path`, or `--blender-path` if a tool is not on
   PATH. On Windows OpenCode needs its native `.exe`, not a `.cmd` wrapper.
   Keep the worker running while processing jobs; Ctrl+C stops it after current
   jobs finish. Starting the worker is explicit; SecureLink does not auto-start
   it, install agents, download models, or sign in on your behalf.

For ComfyUI, install and configure the desired nodes and 3D models yourself and
export the workflow in ComfyUI's **API JSON** format into the workspace. Start
one local ComfyUI server dedicated to a GPU, configured to use only that GPU,
then start a separate SecureLink worker for that server:

```powershell
python -m ui.remote_worker serve --enable comfyui --slots 1 --comfy-gpu GPU-UUID --comfy-url http://127.0.0.1:8188
```

Use the UUID shown by `python -m ui.cli workstation`. For multiple GPUs, run a
separate ComfyUI server and worker for each GPU, on different localhost ports.
The operator must configure each server's GPU visibility and avoid outside
jobs on those servers; SecureLink cannot verify or enforce the server's GPU
assignment. Only localhost HTTP endpoints are supported.

## Control from the other computer

The SSH account must be allowed to launch Python on the workstation, and its
`python` command must find a compatible interpreter. Supply the workstation's
SecureLink project path (not its workspace path):

```powershell
python -m ui.cli remote user@workstation --project 'D:\SecureLink' status
python -m ui.cli remote user@workstation --project 'D:\SecureLink' submit codex 'Review the project' --gpus 0
python -m ui.cli remote user@workstation --project 'D:\SecureLink' list
python -m ui.cli remote user@workstation --project 'D:\SecureLink' get JOB_ID
python -m ui.cli remote user@workstation --project 'D:\SecureLink' events JOB_ID
python -m ui.cli remote user@workstation --project 'D:\SecureLink' cancel JOB_ID
python -m ui.cli remote user@workstation --project 'D:\SecureLink' render 'scene.blend' --frame 1 --gpus 1
python -m ui.cli remote user@workstation --project 'D:\SecureLink' workflow 'workflows\mesh.json'
```

The desktop **Workstation** tab contains the same basic controls. For agents,
the MCP server exposes `remote_workstation`, `remote_upload_file`, and
`remote_download_file`. The workstation endpoint is an SSH-launched JSON
process; SecureLink does not open a new remote-control TCP port. File uploads
and downloads through these MCP tools are limited to 8 MiB and uploads do not
overwrite files. Use the existing SecureLink file-transfer features for larger
assets, placing them in the configured workspace.

Blender renders one frame of an existing `.blend` file inside the workspace,
with automatic Python execution disabled, and writes PNG output to a unique
`securelink-output` folder. Blender's scene and device configuration still
determines the render engine and whether it actually uses a GPU. ComfyUI output
locations depend on the installed nodes and server configuration; the job
result records the output metadata returned by ComfyUI. This release does not
include or automatically install a mesh-generation model or workflow.

## Jobs, GPUs and recovery

Jobs are stored in `~/.securelink/workstation-jobs.sqlite3`. They can request
zero, one, or any number of GPUs and a minimum free memory per card. NVIDIA
devices are detected through `nvidia-smi`; other GPU vendors are not yet
supported. GPU IDs are reserved atomically between workers sharing this queue,
and passed to child processes in `CUDA_VISIBLE_DEVICES`. This is an advisory
environment setting, not a hardware isolation mechanism. Programs that ignore
it, an existing external server, games and other applications can still use
those GPUs. VRAM is not automatically pooled across cards.

With the CLI, `python -m ui.cli jobs list` shows local jobs and `jobs events
JOB_ID` shows their updates. The local MCP tools provide the same operations.
A stable caller-supplied job ID makes repeat submission idempotent. If an SSH
response is lost, the controller reports the job ID; check `jobs.get` before
retrying and reuse that ID. Cancelling
a queued job is immediate; cancelling a running job asks its adapter to stop
the process. Reservations remain held until the process has stopped. Process
trees that cannot be confirmed stopped retain their reservation. Interrupted
jobs are not automatically replayed or released after a worker crash. The
operator must first verify that all related processes stopped, then resolve the
claim with the local recovery command:

```powershell
python -m ui.cli jobs recover JOB_ID --confirm-stopped --reason "process stopped"
```

The queue supports questions and answers, but the initial CLI agent adapters do
not yet translate provider-specific interactive questions or approvals into
this mechanism. Agents may fail or wait according to their own non-interactive
permission settings. The output captured from each successful agent is limited
to its last 256 KiB; provider output may contain sensitive information.
ComfyUI cancellation waits for that workflow to finish rather than stopping all
jobs on the ComfyUI server. If submission or monitoring becomes uncertain,
the worker exits while retaining the GPU reservation for manual inspection.

## Security boundaries and limits

SSH authenticates and encrypts the connection. An SSH account typically has
the operating-system privileges of that account; pairing and access control are
managed by SSH, not by SecureLink's file-transfer trust list. The workspace
path limits SecureLink's file API and initial working directory, but **is not a
sandbox** for agents, Blender, scripts, plugins or the SSH account. Provider
credentials and permissions remain on that workstation. Enable only tools and
grant only accounts you trust. SecureLink does not bypass provider approvals.

The system has not yet been verified across two physical PCs or against real
GPU models. It does not yet offer a one-click installer, automatic WAN setup,
resumable file transfer, OS-level sandboxing, automatic agent question routing,
or a built-in 3D generation model. The desktop workstation tab inventories only
the local machine until a remote SSH target is supplied.
