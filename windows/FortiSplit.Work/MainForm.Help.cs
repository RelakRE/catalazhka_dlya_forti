namespace FortiSplit.Work;

internal sealed partial class MainForm
{
 private Control HelpRow(Control caption,string key)
 {
  var row=new FlowLayoutPanel{AutoSize=true,FlowDirection=FlowDirection.LeftToRight,WrapContents=false,Margin=Padding.Empty,MaximumSize=new Size(690,0)};
  var help=new Button{Text="?",Name="help-"+key,AccessibleName="Как заполнить: "+SettingsHelp.Get(key).Title,AccessibleDescription=SettingsHelp.Get(key).Summary,Width=27,Height=27,FlatStyle=FlatStyle.Flat,BackColor=Color.White,ForeColor=Color.Teal,Font=new Font("Segoe UI",10,FontStyle.Bold),Cursor=Cursors.Hand,Margin=new Padding(8,caption.Margin.Top+Math.Max(0,(caption.Height-27)/2),0,0)};
  help.FlatAppearance.BorderColor=Color.FromArgb(160,185,180);
  help.Click+=(_,_)=>{using var dialog=new SettingsHelpDialog(SettingsHelp.Get(key));dialog.ShowDialog(this);};
  row.Controls.Add(caption);row.Controls.Add(help);return row;
 }
 private static Control HelpSummary(string key)=>new Label{Text=SettingsHelp.Get(key).Summary,AutoSize=true,MaximumSize=new Size(660,0),ForeColor=Color.DimGray,Font=new Font("Segoe UI",9),Margin=new Padding(0,3,0,10)};
 private void HelpField(FlowLayoutPanel parent,string key,Control input)
 {
  parent.Controls.Add(HelpRow(Label(SettingsHelp.Get(key).Title),key));parent.Controls.Add(input);parent.Controls.Add(HelpSummary(key));options.Add(input);
 }
 private void HelpOption(FlowLayoutPanel parent,string key,CheckBox option)
 {
  parent.Controls.Add(HelpRow(option,key));parent.Controls.Add(HelpSummary(key));options.Add(option);
 }
}
