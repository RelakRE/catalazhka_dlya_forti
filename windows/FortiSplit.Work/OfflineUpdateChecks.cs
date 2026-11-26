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
            Storage.Save(link, new UpdateLink(origin, current, Hash(current), PublisherVerified: true));
            previousLink = File.ReadAllBytes(link);
        }

        // A missing parent models the old process having already exited.
        Storage.Save(Path.Combine(staging, "ticket.json"), new UpdateTicket(origin, current, Hash(target), int.MaxValue, 0, PublisherVerified: true));
        using var ready = new EventWaitHandle(false, EventResetMode.AutoReset, @"Local\FortiSplitUpdateReady-" + id);
        Exception? error = null;
        string? restarted = null;
        int result = UpdateInstall.Complete(id, updates, @"Local\FortiSplitUpdateTest-" + id,
            failure => error = failure, path => restarted = path);

        bool processExited = error is IOException { Message: "Новая версия завершилась до запуска." };
        if (error is not null && !processExited) throw error;
        bool linkRestored = previousLink is null ? !File.Exists(link) : File.ReadAllBytes(link).SequenceEqual(previousLink);
        return result == 1 && ready.WaitOne(0) && processExited
            && restarted == current && linkRestored && File.ReadAllBytes(settings).SequenceEqual(profile);
    }

    private static string Hash(string path) => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));
}
