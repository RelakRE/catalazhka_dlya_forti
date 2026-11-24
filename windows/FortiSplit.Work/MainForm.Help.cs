namespace FortiSplit.Work;

internal sealed partial class MainForm
{
    private Control HelpRow(Control caption, string key)
    {
        var row = new TableLayoutPanel { Height = 32, ColumnCount = 2, RowCount = 1, Margin = new Padding(0, 4, 0, 1) };
        row.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        row.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 30));
        row.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        caption.Dock = DockStyle.Fill;
        caption.ForeColor = WorkText;
        if (caption is Label label)
        {
            label.AutoSize = false;
            label.TextAlign = ContentAlignment.MiddleLeft;
            label.Margin = Padding.Empty;
        }
        var topic = SettingsHelp.Get(key);
        var help = Btn("?");
        help.Name = "help-" + key;
        help.AccessibleName = "Справка: " + topic.Title;
        help.AccessibleDescription = topic.Summary;
        help.Dock = DockStyle.Fill;
        help.Font = MetricSmallFont;
        help.Cursor = Cursors.Hand;
        help.Margin = new Padding(3, 3, 0, 3);
        StyleSettingsAction(help);
        help.Click += (_, _) => { using var dialog = new SettingsHelpDialog(topic); dialog.ShowDialog(this); };
        row.Controls.Add(caption, 0, 0);
        row.Controls.Add(help, 1, 0);
        return row;
    }

    private Control SettingsFieldTitle(string key, Control input)
    {
        var topic = SettingsHelp.Get(key);
        input.AccessibleName = topic.Title;
        input.AccessibleDescription = topic.Summary;
        options.Add(input);
        return HelpRow(new Label { Text = topic.Title }, key);
    }

    private void HelpField(FlowLayoutPanel parent, string key, Control input, Control? container = null)
    {
        var title = SettingsFieldTitle(key, input);
        parent.Controls.Add(title);
        FillWidth(parent, title);
        var field = container ?? input;
        field.Margin = new Padding(0, 0, 0, 7);
        parent.Controls.Add(field);
        FillWidth(parent, field);
    }

    private void HelpOption(FlowLayoutPanel parent, string key, CheckBox option, bool showSummary = false)
    {
        var topic = SettingsHelp.Get(key);
        option.AccessibleDescription = topic.Summary;
        option.Margin = Padding.Empty;
        var row = HelpRow(option, key);
        parent.Controls.Add(row);
        FillWidth(parent, row);
        if (showSummary)
        {
            var summary = new Label { Text = topic.Summary, AutoSize = true, ForeColor = WorkMuted, Font = MetricSmallFont, Margin = new Padding(18, 0, 0, 4) };
            parent.Controls.Add(summary);
            ConstrainText(parent, summary);
        }
        options.Add(option);
    }
}
