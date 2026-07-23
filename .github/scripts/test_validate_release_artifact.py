#!/usr/bin/env python3
import hashlib
import importlib.util
import io
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

SCRIPT = Path(__file__).with_name("validate-release-artifact.py")
SPEC = importlib.util.spec_from_file_location("validate_release_artifact", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("release artifact validator must be importable")
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)

LINUX_TARGET = "x86_64-unknown-linux-gnu"
WINDOWS_TARGET = "x86_64-pc-windows-msvc"


class ReleaseArtifactValidatorTests(unittest.TestCase):
    def test_targets_require_a_bounded_unique_valid_list(self) -> None:
        self.assertEqual(validator.parse_targets(f'["{LINUX_TARGET}"]'), [LINUX_TARGET])
        maximum = [f"arch-{index}" for index in range(16)]
        self.assertEqual(validator.parse_targets(str(maximum).replace("'", '"')), maximum)
        with self.assertRaises(SystemExit):
            validator.parse_targets(str([*maximum, "arch-16"]).replace("'", '"'))
        for invalid in ["[]", '"not-a-list"', '["bad target"]', '["x-y", "x-y"]']:
            with self.subTest(invalid=invalid), self.assertRaises(SystemExit):
                validator.parse_targets(invalid)
        validator.require_single_native_target([LINUX_TARGET], LINUX_TARGET)
        with self.assertRaises(SystemExit):
            validator.require_single_native_target(
                [LINUX_TARGET, "aarch64-unknown-linux-gnu"], LINUX_TARGET
            )

    def test_member_paths_reject_traversal_and_absolute_forms(self) -> None:
        for invalid in [
            "../kick",
            "/kick",
            "folder/../kick",
            r"C:\kick",
            r"\\host\kick",
            r"folder\kick",
            "folder//kick",
            "folder/./kick",
            "folder/kick/",
        ]:
            with self.subTest(invalid=invalid), self.assertRaises(SystemExit):
                validator.safe_member_name(invalid)
        self.assertEqual(
            validator.safe_member_name("folder/", directory=True).as_posix(), "folder"
        )
        self.assertEqual(
            validator.safe_member_name("folder", directory=True).as_posix(), "folder"
        )
        for invalid_directory in ["folder//", "folder/./"]:
            with self.subTest(invalid=invalid_directory), self.assertRaises(SystemExit):
                validator.safe_member_name(invalid_directory, directory=True)

    def test_checksum_requires_one_record_for_the_exact_archive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "artifact.tar.xz"
            archive.write_bytes(b"archive")
            digest = hashlib.sha256(b"archive").hexdigest()
            checksum = Path(f"{archive}.sha256")
            checksum.write_text(f"{digest} *{archive.name}\n", encoding="ascii")
            validator.verify_checksum(archive, digest)

            for invalid in [
                f"{digest} *other.tar.xz\n",
                f"{digest}\n",
                f"{digest} *{archive.name}\n{digest} *{archive.name}\n",
                f"{'0' * 64} *{archive.name}\n",
            ]:
                checksum.write_text(invalid, encoding="ascii")
                with self.subTest(invalid=invalid), self.assertRaises(SystemExit):
                    validator.verify_checksum(archive, digest)
            checksum.write_bytes(b"x" * 1025)
            with self.assertRaises(SystemExit):
                validator.verify_checksum(archive, digest)

    def test_tar_requires_the_exact_cargo_dist_layout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "artifact.tar.xz"
            self.write_tar(archive)
            destination = root / "extract"
            destination.mkdir()
            binaries = validator.extract_tar_binaries(
                archive, destination, LINUX_TARGET, {"kickoutchi", "kick"}
            )
            self.assertEqual(set(binaries), {"kickoutchi", "kick"})

            nested = root / "nested.tar.xz"
            self.write_tar(nested, prefix="unexpected")
            with self.assertRaises(SystemExit):
                validator.extract_tar_binaries(
                    nested, root / "unused", LINUX_TARGET, {"kickoutchi", "kick"}
                )

    def test_tar_rejects_symbolic_links(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "symlink.tar.xz"
            prefix = f"kickoutchi-{LINUX_TARGET}"
            with tarfile.open(archive, "w:xz") as bundle:
                directory = tarfile.TarInfo(f"{prefix}/")
                directory.type = tarfile.DIRTYPE
                bundle.addfile(directory)
                link = tarfile.TarInfo(f"{prefix}/kick")
                link.type = tarfile.SYMTYPE
                link.linkname = "kickoutchi"
                bundle.addfile(link)
            with self.assertRaises(SystemExit):
                validator.extract_tar_binaries(
                    archive, Path(temporary) / "unused", LINUX_TARGET, {"kickoutchi", "kick"}
                )

    def test_tar_rejects_non_executable_binaries_and_duplicate_directories(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            non_executable = root / "non-executable.tar.xz"
            self.write_tar(non_executable, executable_mode=0o644)
            with self.assertRaises(SystemExit):
                validator.extract_tar_binaries(
                    non_executable,
                    root / "unused-non-executable",
                    LINUX_TARGET,
                    {"kickoutchi", "kick"},
                )

            duplicate = root / "duplicate-directory.tar.xz"
            prefix = f"kickoutchi-{LINUX_TARGET}"
            with tarfile.open(duplicate, "w:xz") as bundle:
                for _ in range(2):
                    directory = tarfile.TarInfo(f"{prefix}/")
                    directory.type = tarfile.DIRTYPE
                    bundle.addfile(directory)
            with self.assertRaises(SystemExit):
                validator.extract_tar_binaries(
                    duplicate,
                    root / "unused-duplicate",
                    LINUX_TARGET,
                    {"kickoutchi", "kick"},
                )

    def test_zip_requires_the_exact_flat_layout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "artifact.zip"
            self.write_zip(archive)
            destination = root / "extract"
            destination.mkdir()
            binaries = validator.extract_zip_binaries(
                archive, destination, WINDOWS_TARGET, {"kickoutchi.exe", "kick.exe"}
            )
            self.assertEqual(set(binaries), {"kickoutchi.exe", "kick.exe"})

            nested = root / "nested.zip"
            self.write_zip(nested, prefix="unexpected/")
            with self.assertRaises(SystemExit):
                validator.extract_zip_binaries(
                    nested,
                    root / "unused",
                    WINDOWS_TARGET,
                    {"kickoutchi.exe", "kick.exe"},
                )

    def test_tar_and_zip_reject_noncanonical_member_spellings(self) -> None:
        tar_prefix = f"kickoutchi-{LINUX_TARGET}"
        tar_names = [
            rf"{tar_prefix}\kick",
            f"{tar_prefix}//kick",
            f"{tar_prefix}/./kick",
            f"{tar_prefix}/kick/",
        ]
        zip_names = [r"folder\kick.exe", "./kick.exe", "folder//kick.exe", "kick.exe/"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index, member_name in enumerate(tar_names):
                archive = root / f"noncanonical-{index}.tar.xz"
                self.write_tar(archive, member_names={"kick": member_name})
                destination = root / f"tar-output-{index}"
                destination.mkdir()
                with self.subTest(format="tar", member=member_name), self.assertRaises(
                    SystemExit
                ):
                    validator.extract_tar_binaries(
                        archive, destination, LINUX_TARGET, {"kickoutchi", "kick"}
                    )

            for index, member_name in enumerate(zip_names):
                archive = root / f"noncanonical-{index}.zip"
                self.write_zip(archive, member_names={"kick.exe": member_name})
                destination = root / f"zip-output-{index}"
                destination.mkdir()
                with self.subTest(format="zip", member=member_name), self.assertRaises(
                    SystemExit
                ):
                    validator.extract_zip_binaries(
                        archive,
                        destination,
                        WINDOWS_TARGET,
                        {"kickoutchi.exe", "kick.exe"},
                    )

    def test_archive_member_count_rejects_the_first_excess_entry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tar_path = root / "many.tar.xz"
            with tarfile.open(tar_path, "w:xz") as bundle:
                for index in range(validator.ARCHIVE_MEMBERS_MAX + 1):
                    directory = tarfile.TarInfo(f"directory-{index}/")
                    directory.type = tarfile.DIRTYPE
                    bundle.addfile(directory)
            with self.assertRaises(SystemExit):
                validator.extract_tar_binaries(
                    tar_path, root / "tar-output", LINUX_TARGET, {"kickoutchi", "kick"}
                )

            zip_path = root / "many.zip"
            with zipfile.ZipFile(zip_path, "w") as bundle:
                for index in range(validator.ARCHIVE_MEMBERS_MAX + 1):
                    bundle.writestr(f"file-{index}", "x")
            with self.assertRaises(SystemExit):
                validator.extract_zip_binaries(
                    zip_path,
                    root / "zip-output",
                    WINDOWS_TARGET,
                    {"kickoutchi.exe", "kick.exe"},
                )

    def test_version_output_is_bounded_while_the_process_runs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "noisy-version"
            binary.write_text(
                "#!/usr/bin/env python3\n"
                f"print('x' * {validator.VERSION_OUTPUT_BYTES_MAX + 1})\n",
                encoding="utf-8",
            )
            binary.chmod(0o700)
            with self.assertRaises(SystemExit):
                validator.run_version(binary, "1.3.0")

    def test_orchestration_runs_exact_artifact_journeys_with_required_policy(self) -> None:
        digest = "a" * 64
        with tempfile.TemporaryDirectory() as temporary:
            distrib = Path(temporary)
            archive = distrib / f"kickoutchi-{LINUX_TARGET}.tar.xz"
            archive.write_bytes(b"archive")

            def extract(
                actual_archive: Path,
                destination: Path,
                target: str,
                expected: set[str],
            ) -> dict[str, Path]:
                self.assertEqual(actual_archive, archive)
                self.assertEqual(target, LINUX_TARGET)
                self.assertEqual(expected, {"kickoutchi", "kick"})
                return {
                    "kickoutchi": destination / "kickoutchi",
                    "kick": destination / "kick",
                }

            with (
                mock.patch.object(validator, "sha256", return_value=digest) as hash_file,
                mock.patch.object(validator, "verify_checksum") as verify_checksum,
                mock.patch.object(validator, "package_version", return_value="1.3.0"),
                mock.patch.object(validator, "extract_tar_binaries", side_effect=extract),
                mock.patch.object(validator, "run_version") as run_version,
                mock.patch.object(validator.subprocess, "run") as run,
            ):
                result = validator.validate_release_artifact(
                    distrib, f'["{LINUX_TARGET}"]', "Linux", "X64"
                )

            hash_file.assert_called_once_with(archive)
            verify_checksum.assert_called_once_with(archive, digest)
            self.assertEqual(
                [(call.args[0].name, call.args[1]) for call in run_version.call_args_list],
                [("kickoutchi", "1.3.0"), ("kick", "1.3.0")],
            )
            run.assert_called_once()
            command = run.call_args.args[0]
            options = run.call_args.kwargs
            self.assertEqual(
                command,
                ["cargo", "test", "--locked", "--all-features", "--test", "cli_contract"],
            )
            self.assertIs(options["check"], True)
            self.assertEqual(options["timeout"], validator.TEST_TIMEOUT_SECONDS)
            environment = options["env"]
            self.assertEqual(environment["KICKOUTCHI_RELEASE_E2E_REQUIRED"], "1")
            self.assertEqual(Path(environment["KICKOUTCHI_E2E_KICKOUTCHI"]).name, "kickoutchi")
            self.assertEqual(Path(environment["KICKOUTCHI_E2E_KICK"]).name, "kick")
            self.assertEqual(environment["KICKOUTCHI_REQUIRE_LINUX_CAPABILITIES"], "1")
            self.assertEqual(result["artifact_e2e"], "passed")
            self.assertEqual(result["archive_sha256"], digest)
            self.assertEqual(result["capability_policy"], "required")

    @staticmethod
    def write_tar(
        path: Path,
        prefix: str | None = None,
        executable_mode: int = 0o755,
        member_names: dict[str, str] | None = None,
    ) -> None:
        prefix = prefix or f"kickoutchi-{LINUX_TARGET}"
        member_names = member_names or {}
        with tarfile.open(path, "w:xz") as bundle:
            directory = tarfile.TarInfo(f"{prefix}/")
            directory.type = tarfile.DIRTYPE
            bundle.addfile(directory)
            for name in ["CHANGELOG.md", "LICENSE", "README.md", "kickoutchi", "kick"]:
                contents = name.encode("ascii")
                member = tarfile.TarInfo(member_names.get(name, f"{prefix}/{name}"))
                member.size = len(contents)
                member.mode = executable_mode if name in ("kickoutchi", "kick") else 0o644
                bundle.addfile(member, io.BytesIO(contents))

    @staticmethod
    def write_zip(
        path: Path, prefix: str = "", member_names: dict[str, str] | None = None
    ) -> None:
        member_names = member_names or {}
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
            for name in ["CHANGELOG.md", "LICENSE", "README.md", "kickoutchi.exe", "kick.exe"]:
                bundle.writestr(member_names.get(name, f"{prefix}{name}"), name)


if __name__ == "__main__":
    unittest.main()
