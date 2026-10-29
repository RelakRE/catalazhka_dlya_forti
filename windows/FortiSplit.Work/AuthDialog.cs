namespace FortiSplit.Work;

internal sealed class AuthDialog : Form
{
 private readonly Dictionary<string,Control> inputs=new();
 internal readonly CheckBox Remember=new(){Text="Сохранять пароль",AutoSize=true};
 internal AuthDialog(AuthRequest request,Config config,string? saved)
 {
  Text="Вход в VPN";ClientSize=new Size(480,240);AutoSize=true;AutoSizeMode=AutoSizeMode.GrowAndShrink;MinimumSize=new Size(480,240);MaximumSize=new Size(700,900);StartPosition=FormStartPosition.CenterParent;MinimizeBox=false;MaximizeBox=false;Font=new Font("Segoe UI",11);BackColor=Color.White;
  var layout=new FlowLayoutPanel{AutoSize=true,FlowDirection=FlowDirection.TopDown,WrapContents=false,Padding=new Padding(24),MaximumSize=new Size(620,0)};Controls.Add(layout);
  var description=new Label{Text=request.Error.Length>0?request.Error:request.Message.Length>0?request.Message:"Введите данные, запрошенные сервером VPN.",AutoSize=true,MaximumSize=new Size(420,220),Margin=new Padding(0,0,0,18)};layout.Controls.Add(description);
  if(request.Attempt>1)layout.Controls.Add(new Label{Text=$"Повторная форма входа ({request.Attempt}/6). Вход ещё не подтверждён. Причина повтора может быть не указана.",AutoSize=true,MaximumSize=new Size(420,140),ForeColor=Color.DarkOrange,Margin=new Padding(0,0,0,12)});
  foreach(var field in request.Fields){layout.Controls.Add(new Label{Text=AuthPolicy.Caption(field,request),AutoSize=true,MaximumSize=new Size(420,80),Margin=new Padding(0,8,0,4)});Control input;
   if(field.Type==3){var combo=new ComboBox{DropDownStyle=ComboBoxStyle.DropDownList,Width=420};combo.DataSource=field.Choices;combo.DisplayMember="Label";combo.ValueMember="Value";input=combo;}
   else input=new TextBox{Width=420,UseSystemPasswordChar=field.Type is 2 or 5,Text=AuthPolicy.IsUser(field)?config.User:AuthPolicy.IsPassword(field,request)?saved??"":"",MaxLength=4096};
   inputs[field.Name]=input;layout.Controls.Add(input);
  }
  foreach(var field in request.Fields.Where(AuthPolicy.IsUser))if(inputs[field.Name] is TextBox username)username.TextChanged+=(_,_)=>{
   foreach(var password in request.Fields.Where(f=>AuthPolicy.IsPassword(f,request)))if(inputs[password.Name] is TextBox secret)secret.Clear();
  };
  if(request.Fields.Any(f=>AuthPolicy.IsPassword(f,request))){Remember.Checked=config.RememberPassword;Remember.Margin=new Padding(0,12,0,10);layout.Controls.Add(Remember);}
  var buttons=new FlowLayoutPanel{AutoSize=true,FlowDirection=FlowDirection.LeftToRight,Margin=new Padding(0,16,0,0)};
  var ok=new Button{Text="Продолжить",DialogResult=DialogResult.OK,Width=190,Height=40};var cancel=new Button{Text="Отмена",DialogResult=DialogResult.Cancel,Width=190,Height=40};buttons.Controls.AddRange([ok,cancel]);layout.Controls.Add(buttons);AcceptButton=ok;CancelButton=cancel;
 }
 internal AuthReply Reply()=>new(DialogResult!=DialogResult.OK,inputs.ToDictionary(x=>x.Key,x=>x.Value is ComboBox combo?(string?)combo.SelectedValue??"":x.Value.Text));
 protected override void Dispose(bool disposing){if(disposing)foreach(var input in inputs.Values)if(input is TextBox text)text.Clear();base.Dispose(disposing);}
}
