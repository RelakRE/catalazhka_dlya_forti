using System.IO.Compression;
using System.Security.Cryptography;

namespace FortiSplit.Work;

internal static class OfflineUpdateChecks
{
    internal static bool FailedLaunchRestoresPrevious(string root, bool hasPreviousLink)
    {
        string id = Guid.NewGuid().ToString("N");
        string updates = Path.Combine(root, "updates");
        string staging = Path.Combine(updates, "staging", id);
        string version = Path.Combine(updates, "versions", id);
        string links = Path.Combine(updates, "links");
        Directory.CreateDirectory(staging);
        Directory.CreateDirectory(version);
        Directory.CreateDirectory(links);

        string settings = Path.Combine(root, "settings.json");
        Storage.Save(settings, new Config { Server = "https://vpn.example.com", User = "sample.user" });
        byte[] profile = File.ReadAllBytes(settings);
        string origin = Path.Combine(root, "Forti Split.exe");
        string target = Path.Combine(version, "Forti Split.exe");
        File.WriteAllText(origin, "original installation");
        // With no arguments where.exe exits without signalling that the application is ready.
        File.Copy(Path.Combine(Environment.SystemDirectory, "where.exe"), target);
        Storage.Save(Path.Combine(version, ".fortisplit-origin.json"), new UpdateMarker(origin));

        string current = origin;
        string link = UpdateInstall.LinkPath(origin, links);
        byte[]? previousLink = null;
        if (hasPreviousLink)
        {
            string previous = Path.Combine(updates, "versions", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(previous);
            current = Path.Combine(previous, "Forti Split.exe");
            File.WriteAllText(current, "previous installation");
            Storage.Save(Path.Combine(previous, ".fortisplit-origin.json"), new UpdateMarker(origin));
            Storage.Save(link, new UpdateLink(origin, current));
            previousLink = File.ReadAllBytes(link);
        }

        // A missing parent models the old process having already exited.
        using var publisher = RSA.Create(3072);
        string publisherKey = Convert.ToBase64String(publisher.ExportSubjectPublicKeyInfo());
        SignExecutable(target, publisher);
        Storage.Save(Path.Combine(staging, "ticket.json"), new UpdateTicket(origin, current, int.MaxValue, 0));
        using var ready = new EventWaitHandle(false, EventResetMode.AutoReset, @"Local\FortiSplitUpdateReady-" + id);
        Exception? error = null;
        string? restarted = null;
        int result = UpdateInstall.Complete(id, updates, @"Local\FortiSplitUpdateTest-" + id, current, publisherKey,
            failure => error = failure, path => restarted = path);

        bool processExited = error is IOException { Message: "Новая версия завершилась до запуска." };
        if (error is not null && !processExited) throw error;
        bool linkRestored = previousLink is null ? !File.Exists(link) : File.ReadAllBytes(link).SequenceEqual(previousLink);
        return result == 1 && ready.WaitOne(0) && processExited
            && restarted == current && linkRestored && File.ReadAllBytes(settings).SequenceEqual(profile);
    }

    internal static void CheckLaunchProof(string directory, Dictionary<string, bool> checks)
    {
        Directory.CreateDirectory(directory);
        string executable = Path.Combine(directory, "Forti Split.exe");
        File.WriteAllText(executable, "original");
        using var publisher = RSA.Create(3072);
        string key = Convert.ToBase64String(publisher.ExportSubjectPublicKeyInfo());
        SignExecutable(executable, publisher);
        checks["update_launch_accepts_valid_proof"] = UpdateInstall.CanConfirmLaunch(executable, key);
        checks["update_launch_requires_embedded_key"] = !UpdateInstall.CanConfirmLaunch(executable, null);

        File.WriteAllText(executable, "modified");
        checks["update_rejects_executable_different_from_signed_archive"] = !UpdateInstall.CanConfirmLaunch(executable, key);

        File.WriteAllText(executable, "original");
        File.Delete(Path.Combine(directory, UpdateInstall.ProofSignature));
        checks["legacy_update_without_proof_cannot_confirm_launch"] = !UpdateInstall.CanConfirmLaunch(executable, key);
        File.WriteAllText(Path.Combine(directory, UpdateInstall.ProofAttestation), "{}");
        checks["invalid_build_attestation_cannot_confirm_launch"] = !UpdateInstall.CanConfirmLaunch(executable, null);
    }

    private static void SignExecutable(string executable, RSA publisher)
    {
        string directory = Path.GetDirectoryName(executable)!;
        string archive = Path.Combine(directory, UpdateInstall.ProofArchive);
        using (var zip = ZipFile.Open(archive, ZipArchiveMode.Create))
            zip.CreateEntryFromFile(executable, "Forti Split.exe");
        using var input = File.OpenRead(archive);
        byte[] signature = publisher.SignHash(SHA256.HashData(input), HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        File.WriteAllBytes(Path.Combine(directory, UpdateInstall.ProofSignature), signature);
    }
}
