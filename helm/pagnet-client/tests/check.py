"""Offline chart checks; requires Helm 3+, Python 3 and PyYAML."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import yaml

CHART = Path(__file__).resolve().parents[1]


def helm(*args, succeeds=True):
    result = subprocess.run(
        ["helm", *args], capture_output=True, text=True, check=False
    )
    if (result.returncode == 0) != succeeds:
        raise AssertionError(result.stdout + result.stderr)
    return result.stdout


def render(*values):
    output = helm(
        "template", "test", str(CHART),
        "--set-string", "enrollment.existingSecret=enrollment", *values
    )
    return list(yaml.safe_load_all(output))


class ChartChecks(unittest.TestCase):
    def test_lint(self):
        helm("lint", str(CHART), "--set-string", "enrollment.existingSecret=enrollment")

    def test_default_security_and_commands(self):
        docs = render()
        self.assertEqual([d["kind"] for d in docs], ["PersistentVolumeClaim", "Deployment"])
        deployment = docs[1]
        self.assertEqual(deployment["spec"]["replicas"], 1)
        self.assertEqual(deployment["spec"]["strategy"], {"type": "Recreate"})
        pod = deployment["spec"]["template"]["spec"]
        self.assertFalse(pod["automountServiceAccountToken"])
        for key in ("runAsUser", "runAsGroup", "fsGroup"):
            self.assertEqual(pod["securityContext"][key], 10001)
        self.assertTrue(pod["securityContext"]["runAsNonRoot"])
        self.assertEqual(pod["securityContext"]["seccompProfile"]["type"], "RuntimeDefault")
        main = pod["containers"][0]
        init = pod["initContainers"][0]
        self.assertEqual(init["image"], main["image"])
        self.assertEqual(main["command"], ["pagnet"])
        self.assertEqual(main["args"], ["serve", "--state-dir", "/var/lib/pagnet/state",
                         "--account", "default", "--non-interactive", "--no-auto-update",
                         "--require-enrolled"])
        self.assertEqual(main["env"], [{"name": "HOME", "value": "/var/lib/pagnet/home"},
                         {"name": "PAGNET_SCAN_WORKSPACES", "value": "0"}])
        self.assertEqual(init["env"][1]["valueFrom"]["secretKeyRef"],
                         {"name": "enrollment", "key": "token", "optional": True})
        for container in (init, main):
            self.assertEqual(container["securityContext"], {
                "allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                "capabilities": {"drop": ["ALL"]}})
        self.assertEqual(pod["volumes"][1], {"name": "workspace", "emptyDir": {}})
        self.assertEqual(pod["volumes"][2], {"name": "tmp", "emptyDir": {}})
        self.assertFalse(any("hostPath" in volume for volume in pod["volumes"]))
        self.assertEqual(docs[0]["metadata"]["annotations"]["helm.sh/resource-policy"], "keep")

    def test_existing_claims_and_overrides(self):
        docs = render("--set-string", "persistence.existingClaim=state",
                      "--set-string", "workspace.existingClaim=work",
                      "--set-string", "image.tag=release-test",
                      "--set-string", "enrollment.name=host-test")
        self.assertEqual(len(docs), 1)
        pod = docs[0]["spec"]["template"]["spec"]
        self.assertEqual(pod["volumes"][:2], [
            {"name": "state", "persistentVolumeClaim": {"claimName": "state"}},
            {"name": "workspace", "persistentVolumeClaim": {"claimName": "work"}}])
        self.assertEqual(pod["containers"][0]["image"], "ghcr.io/pagnet-code/pagnet:release-test")
        self.assertEqual(pod["initContainers"][0]["env"][3]["value"], "host-test")

    def test_storage_class(self):
        self.assertNotIn("storageClassName", render()[0]["spec"])
        self.assertEqual(render("--set-string", "persistence.storageClass=")[0]
                         ["spec"]["storageClassName"], "")
        self.assertEqual(render("--set-string", "persistence.storageClass=fast")[0]
                         ["spec"]["storageClassName"], "fast")

    def test_private_registry_pull_secret(self):
        default_pod = render()[1]["spec"]["template"]["spec"]
        self.assertNotIn("imagePullSecrets", default_pod)
        pod = render("--set-string", "image.pullSecrets[0]=ghcr-auth")[1]["spec"]["template"]["spec"]
        self.assertEqual(pod["imagePullSecrets"], [{"name": "ghcr-auth"}])

    def test_digest_pins_both_containers(self):
        digest = "sha256:" + "a" * 64
        pod = render("--set-string", f"image.digest={digest}")[1]["spec"]["template"]["spec"]
        for container in [*pod["initContainers"], *pod["containers"]]:
            self.assertEqual(container["image"], f"ghcr.io/pagnet-code/pagnet@{digest}")
        helm("template", "test", str(CHART), "--set-string",
             "enrollment.existingSecret=enrollment", "--set-string",
             "image.digest=sha256:invalid", succeeds=False)

    def test_reject_missing_secret_and_plaintext_token(self):
        helm("template", "test", str(CHART), succeeds=False)
        helm("template", "test", str(CHART), "--set-string",
             "enrollment.existingSecret=enrollment", "--set-string",
             "enrollment.token=forbidden", succeeds=False)
        helm("template", "test", str(CHART), "--set-string",
             "enrollment.existingSecret=enrollment", "--set-string",
             "enrollment.server=", succeeds=False)

    def run_init(self, content=None, token="test-token", partial=False):
        script = render()[1]["spec"]["template"]["spec"]["initContainers"][0]["args"][0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / "state"
            if content is not None:
                config = state / "accounts/default/config.yaml"
                config.parent.mkdir(parents=True)
                config.write_text(content)
            if partial:
                state.mkdir()
                (state / "identity.json").write_text("partial")
            script = script.replace("/var/lib/pagnet/state", str(state))
            executable = root / "pagnet"
            executable.write_text('#!/bin/sh\nprintf "%s\\n" "$@"\n')
            executable.chmod(0o700)
            env = dict(os.environ, HOME=str(root / "home"), PATH=str(root) + os.pathsep + os.environ["PATH"],
                       PAGNET_ENROLL_SERVER="https://example.test",
                       PAGNET_ENROLL_NAME="test-host", PAGNET_ENROLL_TOKEN=token)
            return subprocess.run(["/bin/sh", "-ec", script], env=env,
                                  capture_output=True, text=True, check=False)

    def test_fresh_enrollment(self):
        result = self.run_init()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines()[:2], ["enroll", "--non-interactive"])
        self.assertIn("--roots\n/workspace\n--roots-mode\nallow_list\n", result.stdout)
        self.assertNotIn("test-token", result.stdout)

    def test_existing_config_never_enrolls(self):
        for content in ("hostId: existing\n", "malformed: [yaml"):
            result = self.run_init(content, token="")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "")

    def test_partial_state_fails(self):
        self.assertNotEqual(self.run_init(partial=True).returncode, 0)

    def test_missing_token_and_empty_config_fail(self):
        self.assertNotEqual(self.run_init(token="").returncode, 0)
        self.assertNotEqual(self.run_init(content="").returncode, 0)


if __name__ == "__main__":
    unittest.main()
