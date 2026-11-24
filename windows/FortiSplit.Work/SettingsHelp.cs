namespace FortiSplit.Work;

internal sealed record SettingsHelpTopic(string Title,string Summary,string Instructions,string Example="")
{
 internal string Content()
 {
  return Summary+(Example.Length>0?"\r\n\r\nВымышленный пример: замените своими данными\r\n"+Example:"")+"\r\n\r\n"+Instructions;
 }
}

internal static class SettingsHelp
{
 private static readonly Dictionary<string,SettingsHelpTopic> Topics=new()
 {
  ["auto-rdp"]=new("Открывать RDP после подключения","Открывает выбранный рабочий стол после подключения VPN.",
   "Выберите файл в поле «Файл RDP» и включите автозапуск.\r\n\r\nЧтобы открывать RDP вручную, оставьте галочку выключенной и используйте кнопку «Открыть RDP» в настройках."),
  ["auto-tc"]=new("Открывать TrueConf после подключения","Открывает TrueConf после подключения VPN.",
   "В разделе «Приложения» укажите программу и сервер TrueConf. Включите автозапуск, если TrueConf должен открываться после подключения VPN."),
  ["auto-connect"]=new("Подключаться при открытии приложения","Начинает вход в VPN при запуске Forti Split.",
   "Включите, чтобы начинать подключение автоматически. При необходимости Windows запросит разрешение, а VPN — код подтверждения.\r\n\r\nОставьте галочку выключенной, чтобы подключаться по кнопке."),
  ["login"]=new("Рабочий логин","Имя учётной записи для входа в VPN.",
   "Введите логин из FortiClient в формате, выданном ИТ: имя, DOMAIN\\имя или адрес почты. Пароль вводится в окне входа.\r\n\r\nЛогин можно указать и позже, в окне входа.","demo.operator"),
  ["remember"]=new("Сохранять пароль","После успешного входа сохраняет пароль в хранилище Windows.",
   "Включите, чтобы подставлять пароль при следующем входе. Коды 2FA и пароль в JSON-профиле не сохраняются.\r\n\r\nЕсли снять галочку и сохранить настройки, пароль этой учётной записи будет удалён из хранилища Windows."),
  ["rdp"]=new("Файл RDP","Файл .rdp с настройками удалённого рабочего стола.",
   "Нажмите «Выбрать» или введите путь вручную. Настройки компьютера и шлюза берутся из файла.\r\n\r\nЕсли RDP не используете, оставьте поле пустым и выключите его автозапуск.",@"C:\Demo\Work\sample.rdp"),
  ["vpn"]=new("Сервер VPN","HTTPS-адрес сервера входа в VPN.",
   "Укажите адрес и порт из FortiClient в формате https://имя-сервера:порт. Стандартный порт 443 можно не писать. Добавляйте рабочие сайты в разделе «Рабочие адреса».\r\n\r\nЕсли VPN уже подключается, сохраните существующий адрес.","https://vpn.demo.example.org:8443"),
  ["tc-program"]=new("Программа TrueConf","Путь к установленной программе TrueConf на этом компьютере.",
   "Нажмите «Выбрать» или введите путь вручную. Адрес сервера вводится в следующем поле.\r\n\r\nЕсли TrueConf не используете, выключите его автозапуск и оставьте поле пустым.",@"C:\Demo\Apps\TrueConf\TrueConf.exe"),
  ["tc-server"]=new("Сервер TrueConf","Имя или IPv4 сервера TrueConf, доступного через VPN.",
   "Найдите адрес в настройках TrueConf или узнайте у ИТ. Введите имя или IPv4 без https://, порта и пути.\r\n\r\nForti Split добавляет маршрут к серверу; подключение и учётная запись настраиваются в TrueConf. Если программа не используется, оставьте поле пустым.","video.demo.example.org"),
  ["tc-port"]=new("Порт TrueConf","Номер порта TrueConf в профиле приложения.",
   "Если ИТ не выдал другой порт, оставьте 4307. Допустимы числа от 1 до 65535.\r\n\r\nForti Split сохраняет значение в профиле, но не меняет порт в TrueConf и не ограничивает им VPN-маршрут.","4500"),
  ["sites"]=new("Добавить рабочий адрес","Рабочий ресурс, доступный через VPN.",
   "Введите одну ссылку, имя сервера или IPv4 и нажмите «Добавить». Сохраните изменения кнопкой внизу. При подключённом VPN кнопка называется «Применить рабочие адреса».\r\n\r\nИз ссылки приложение сохраняет имя сервера. При подключении и применении адресов имена разрешаются через DNS VPN.\r\n\r\nПри подключённом VPN выберите запись и нажмите «Проверить адрес». В открывшемся окне выберите, что проверить: маршрут и пинг, один из сервисов или свой TCP-порт.","https://portal.demo.example.org:9443/start\r\nfiles.demo.example.org\r\n192.0.2.47"),
  ["domains"]=new("Рабочие DNS-домены","Домены внутренних имён для корпоративного DNS.",
   "Введите домены своей организации через запятую. Указать их может ИТ. Не добавляйте https://, порт, путь, IP, знак * или точку в начале.\r\n\r\nПоле необязательное: для каждого явно указанного рабочего имени приложение создаёт отдельное DNS-правило. Существующие домены лучше сохранить.","demo.example.org, branch.example.org"),
  ["advanced"]=new("Разделы настроек","VPN, рабочие адреса, приложения и обслуживание.",
   "Выберите нужный раздел сверху. При подключённом VPN рабочие адреса и DNS-домены можно изменить кнопкой «Применить рабочие адреса» внизу настроек."),
  ["save"]=new("Сохранить настройки","Сохраняет настройки для следующих подключений.",
   "Укажите сервер VPN, проверьте выбранные файлы и нажмите «Сохранить настройки». Пароль вводится при входе.\r\n\r\nПри подключённом VPN кнопка внизу называется «Применить рабочие адреса». Она сохраняет рабочие сайты и DNS-домены и обновляет их маршруты."),
  ["profiles"]=new("Профили","Импортирует или экспортирует настройки.",
   "Выберите профиль для импорта и проверьте локальные пути. Экспорт сохраняет серверы, адреса, логин и настройки в приватном файле, без паролей и кодов 2FA. Передавайте файл по разрешённому внутреннему каналу."),
  ["import"]=new("Импорт профиля","Заполняет настройки из приватного JSON-профиля.",
   "Выберите файл .json, полученный от ИТ или ранее экспортированный из Forti Split для Windows. Проверьте логин и пути к файлам, затем нажмите «Сохранить настройки».\r\n\r\nИмпорт не подключает VPN. Пароли и коды 2FA в профиль не входят."),
  ["export"]=new("Экспорт профиля","Сохраняет настройки в файл для копии или переноса.",
   "Выберите место для файла .local.json. В нём будут серверы, рабочие адреса, логин, пути к программам и выбранные опции; пароля и кодов 2FA в файле нет.\r\n\r\nНа другом компьютере пути к программам могут измениться. Передавайте профиль по разрешённому внутреннему каналу: он содержит приватные рабочие данные.")
 };
 internal static SettingsHelpTopic Get(string key)=>Topics[key];
}

internal sealed class SettingsHelpDialog : Form
{
 internal SettingsHelpDialog(SettingsHelpTopic topic)
 {
  Text="Как заполнить: "+topic.Title;ClientSize=new Size(680,540);MinimumSize=new Size(560,420);StartPosition=FormStartPosition.CenterParent;
  Font=new Font("Segoe UI",11);BackColor=Color.White;MinimizeBox=false;MaximizeBox=false;
  var layout=new TableLayoutPanel{Dock=DockStyle.Fill,Padding=new Padding(24),ColumnCount=1,RowCount=3};
  layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));layout.RowStyles.Add(new RowStyle(SizeType.Percent,100));layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));Controls.Add(layout);
  layout.Controls.Add(new Label{Text=topic.Title,AutoSize=true,MaximumSize=new Size(620,0),Font=new Font("Segoe UI",18),Margin=new Padding(0,0,0,14)},0,0);
  layout.Controls.Add(new RichTextBox{Text=topic.Content(),ReadOnly=true,DetectUrls=false,BorderStyle=BorderStyle.None,BackColor=Color.White,ForeColor=Color.FromArgb(35,45,50),Font=Font,Dock=DockStyle.Fill,ScrollBars=RichTextBoxScrollBars.Vertical,Margin=new Padding(0,0,0,16),AccessibleName="Инструкция по заполнению"},0,1);
  var actions=new FlowLayoutPanel{Dock=DockStyle.Fill,AutoSize=true,FlowDirection=FlowDirection.RightToLeft,WrapContents=false,Margin=Padding.Empty};
  var close=new Button{Text="Понятно",DialogResult=DialogResult.OK,Width=130,Height=40,FlatStyle=FlatStyle.Flat,Margin=Padding.Empty};actions.Controls.Add(close);layout.Controls.Add(actions,0,2);AcceptButton=close;CancelButton=close;
 }
}
