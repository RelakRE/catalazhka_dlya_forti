namespace FortiSplit.Work;

internal sealed partial class MainForm
{
 private Control HelpRow(Control caption,string key)
 {
  int height=caption is TableLayoutPanel?64:key=="advanced"?54:40;
  var row=new TableLayoutPanel{AutoSize=false,Height=height,ColumnCount=2,RowCount=1,Margin=new Padding(0,0,0,8)};
  row.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));row.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,36));
  row.RowStyles.Add(new RowStyle(SizeType.Percent,100));
  caption.Dock=DockStyle.Fill;
  var help=new Button{Text="?",Name="help-"+key,AccessibleName="Справка: "+SettingsHelp.Get(key).Title,AccessibleDescription=SettingsHelp.Get(key).Summary,Dock=DockStyle.Fill,Height=32,Font=new Font("Segoe UI",10,FontStyle.Bold),Cursor=Cursors.Hand,Margin=new Padding(4,3,0,3)};
  help.Click+=(_,_)=>{using var dialog=new SettingsHelpDialog(SettingsHelp.Get(key));dialog.ShowDialog(this);};
  row.Controls.Add(caption,0,0);row.Controls.Add(help,1,0);return row;
 }
 private static Label HelpSummary(string key)=>new Label{Text=SettingsHelp.Get(key).Summary,AutoSize=true,MaximumSize=new Size(660,0),ForeColor=SystemColors.ControlText,Font=new Font("Segoe UI",9),Margin=new Padding(0,3,0,10)};
 private void HelpField(FlowLayoutPanel parent,string key,Control input,Control? container=null)
 {
  input.AccessibleName=SettingsHelp.Get(key).Title;input.AccessibleDescription=SettingsHelp.Get(key).Summary;
  var title=HelpRow(Label(SettingsHelp.Get(key).Title),key);parent.Controls.Add(title);FillWidth(parent,title);
  var field=container??input;field.Margin=new Padding(0,field.Margin.Top,0,field.Margin.Bottom);parent.Controls.Add(field);FillWidth(parent,field);
  var summary=HelpSummary(key);parent.Controls.Add(summary);ConstrainText(parent,summary);options.Add(input);
 }
 private void HelpOption(FlowLayoutPanel parent,string key,CheckBox option,bool showSummary=true)
 {
  option.AccessibleDescription=SettingsHelp.Get(key).Summary;
  var row=HelpRow(option,key);parent.Controls.Add(row);FillWidth(parent,row);if(showSummary){var summary=HelpSummary(key);parent.Controls.Add(summary);ConstrainText(parent,summary);}options.Add(option);
 }
}
