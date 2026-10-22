using System.Security.Principal;

namespace FortiSplit.Companion;

internal static class Program
{
    [STAThread]
    private static int Main(string[] arguments)
    {
        ApplicationConfiguration.Initialize();
        if (arguments.Length == 3 && arguments[0] == "--self-test")
            return SelfTests.Run(arguments[1], arguments[2]);
        if (arguments.Length > 0 && !(arguments.Length == 1 && arguments[0] == "--login")) return 2;
        try
        {
            var sid = WindowsIdentity.GetCurrent().User?.Value ?? throw new IOException("Неизвестный пользователь.");
            using var single = new Mutex(true, @"Local\FortiSplitCompanion-" + sid, out var first);
            if (!first)
            {
                MessageBox.Show("Companion уже запущен. Откройте его из значка в трее.", "Forti Split");
                return 0;
            }
            var directory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Forti Split Companion");
            using var form = new MainForm(new SettingsStore(directory));
            Application.Run(form);
            return 0;
        }
        catch (Exception error)
        {
            MessageBox.Show("Приложение не запущено. VPN и маршруты не изменялись.\n" + error.Message, "Forti Split");
            return 1;
        }
    }
}
