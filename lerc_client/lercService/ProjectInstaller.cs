using System.Collections;
using System.ComponentModel;
using System.Configuration.Install;
using System.ServiceProcess;
using System.IO;

namespace lercService
{
    [RunInstaller(true)]
    public partial class ProjectInstaller : Installer
    {
        public ProjectInstaller()
        {
            InitializeComponent();
        }

        private void serviceInstaller1_AfterInstall(object sender, InstallEventArgs e)
        {
            // if set to start automatically then start the service after installation
            if (serviceInstaller1.StartType == ServiceStartMode.Automatic)
            {
                new ServiceController(serviceInstaller1.ServiceName).Start();
            }
        }

        private void serviceProcessInstaller1_AfterInstall(object sender, InstallEventArgs e)
        {

        }

        public override void Install(IDictionary stateSaver)
        {
            base.Install(stateSaver);

            using (StreamWriter sw = new StreamWriter(Context.Parameters["targetdir"] + "config.txt"))
            {
                sw.WriteLine("company: " + Context.Parameters["company"]);
                sw.WriteLine("reconnectdelay: " + Context.Parameters["reconnectdelay"]);
                sw.WriteLine("chunksize: " + Context.Parameters["chunksize"]);
                sw.WriteLine("serverurls: " + Context.Parameters["serverurls"]);
            }
        }

        public override void Uninstall(IDictionary savedState)
        {
            try
            {
                File.Delete(Context.Parameters["targetdir"] + "config.txt");
                File.Delete(Context.Parameters["targetdir"] + "log.txt");
            }
            catch { }
            base.Uninstall(savedState);
        }
    }
}
